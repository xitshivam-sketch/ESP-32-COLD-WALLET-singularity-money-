/*
  
  AP:
    SSID: SingularityMoney
    PASS: stored in NVS; default = 1451XINXSHIV
    URL : http://192.168.4.1
*/
struct TxKeys;   // tells compiler "this type exists"

#include <Arduino.h>
#include <WiFi.h>
#include <WebServer.h>
#include <Preferences.h>
#include <esp_bt.h>
#include <nvs_flash.h>
#include <vector>

#include <Crypto.h>
#include <KeccakCore.h>

#include "mbedtls/ecp.h"
#include "mbedtls/md.h"
#include "mbedtls/pkcs5.h"
#include "mbedtls/gcm.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/bignum.h"

// =================== BUILD SWITCH ===================
#define ENABLE_WEB_UI 1
// ====================================================

static const char* DEVICE_NAME = "Singularity Money";
static const char* DEVICE_CODE = "1451XINXSHIV";
static const char* VERSION_STR = "0.1V";

static const char* DEFAULT_SSID = "SingularityMoney";
static const char* DEFAULT_PASS = "1451XINXSHIV";

WebServer server(80);
Preferences prefs;

// ---------------- SESSION (RAM only) ----------------
String sessionToken = "";
String sessionPin   = "";
bool   sessionAuthed = false;

// Decrypted wallet in RAM after unlock (only in session)
String walletAddress = "";
String privateKey    = "";

// Persisted balances (wei strings)
String ethWei  = "0";
String bnbWei  = "0";

// Persisted prices (USD strings)
String priceETH  = "0";
String priceBNB  = "0";

// ---------------- NVS KEYS ----------------
static const char* NS      = "sm";
static const char* NS_WIFI = "smwifi";

static const char* K_HASPIN = "hasPin";
static const char* K_SALT   = "salt";     // 16 bytes
static const char* K_PINH   = "pinh";     // 32 bytes
static const char* K_ADDR   = "addr";     // string
static const char* K_IV     = "iv";       // 12 bytes
static const char* K_TAG    = "tag";      // 16 bytes
static const char* K_CIPH   = "ciph";     // ciphertext bytes

static const char* K_FAILS  = "fails";    // wrong PIN attempts

static const char* K_ETHWEI  = "ethWei";
static const char* K_BNBWEI  = "bnbWei";
static const char* K_PETH    = "pETH";
static const char* K_PBNB    = "pBNB";

static const char* K_LASTTOTAL = "lastTotal"; // float-as-string snapshot for %+ line

// Admin password (4-10 digits)
static const char* K_HASADM = "hasAdm";
static const char* K_ASALT  = "aSalt";    // 16 bytes
static const char* K_AHASH  = "aHash";    // 32 bytes

// WiFi settings
static const char* K_WIFISSID = "ssid";
static const char* K_WIFIPASS = "pass";

// TX history (last 3) — FIELD-based (reliable, avoids broken JSON blobs)
// slot 0
static const char* K_T0_C  = "t0c";   // coin
static const char* K_T0_TO = "t0to";  // to
static const char* K_T0_A  = "t0a";   // amount
static const char* K_T0_N  = "t0n";   // nonce u64
static const char* K_T0_G  = "t0g";   // gasGwei u64
static const char* K_T0_L  = "t0l";   // gasLimit u64
static const char* K_T0_ID = "t0id";  // chainId u32
static const char* K_T0_H  = "t0h";   // txHash
static const char* K_T0_R  = "t0r";   // rawTx
static const char* K_T0_S  = "t0s";   // status
static const char* K_T0_T  = "t0t";   // tsec u32
// slot 1
static const char* K_T1_C  = "t1c";
static const char* K_T1_TO = "t1to";
static const char* K_T1_A  = "t1a";
static const char* K_T1_N  = "t1n";
static const char* K_T1_G  = "t1g";
static const char* K_T1_L  = "t1l";
static const char* K_T1_ID = "t1id";
static const char* K_T1_H  = "t1h";
static const char* K_T1_R  = "t1r";
static const char* K_T1_S  = "t1s";
static const char* K_T1_T  = "t1t";
// slot 2
static const char* K_T2_C  = "t2c";
static const char* K_T2_TO = "t2to";
static const char* K_T2_A  = "t2a";
static const char* K_T2_N  = "t2n";
static const char* K_T2_G  = "t2g";
static const char* K_T2_L  = "t2l";
static const char* K_T2_ID = "t2id";
static const char* K_T2_H  = "t2h";
static const char* K_T2_R  = "t2r";
static const char* K_T2_S  = "t2s";
static const char* K_T2_T  = "t2t";

// Price history snapshots (last 5 JSON strings)
static const char* K_PH0 = "ph0";
static const char* K_PH1 = "ph1";
static const char* K_PH2 = "ph2";
static const char* K_PH3 = "ph3";
static const char* K_PH4 = "ph4";

static const int PBKDF2_ITERS = 60000;
static const int MAX_FAILS    = 3;

// =====================================================
// Put structs BEFORE any functions that use them
// =====================================================
struct TxRecord {
  String coin;        // "BNB" or "ETH"
  String to;
  String amountCoin;  // human string like "0.01"
  uint64_t nonce = 0;
  uint64_t gasGwei = 0;
  uint64_t gasLimit = 21000;
  uint32_t chainId = 56;
  String txHash;      // 0x...
  String rawTx;       // 0x...
  String status;      // "pending" | "success" | "failed"
  uint32_t tsec = 0;  // uptime seconds
};

// =================== HELPERS ===================
static inline void sendJSON(const String& s, int code = 200) {
  server.send(code, "application/json", s);
}

static inline String jsonEscape(const String& in) {
  String o; o.reserve(in.length() + 16);
  for (size_t i = 0; i < in.length(); i++) {
    char c = in[i];
    if (c == '\\') o += "\\\\";
    else if (c == '"') o += "\\\"";
    else if (c == '\n') o += "\\n";
    else if (c == '\r') o += "\\r";
    else if (c == '\t') o += "\\t";
    else o += c;
  }
  return o;
}

static inline String randomToken() {
  uint8_t r[16];
  esp_fill_random(r, 16);
  String t;
  for (int i = 0; i < 16; i++) {
    if (r[i] < 0x10) t += "0";
    t += String(r[i], HEX);
  }
  return t;
}

static inline bool authed() {
  if (!server.hasArg("t")) return false;
  return sessionAuthed && (server.arg("t") == sessionToken) && sessionToken.length() > 0;
}

static inline bool hasWalletRAM() {
  return walletAddress.length() > 0 && privateKey.length() > 0;
}

static inline void wipeRAMSecrets() {
  for (size_t i = 0; i < privateKey.length(); i++) privateKey.setCharAt(i, '\0');
  privateKey = "";
  walletAddress = "";
  sessionPin = "";
  sessionToken = "";
  sessionAuthed = false;
}

static inline uint32_t upSeconds() {
  return (uint32_t)(millis() / 1000UL);
}

// =================== WEI / COIN ===================
static inline String weiToCoin(String weiStr) {
  while (weiStr.length() > 1 && weiStr[0] == '0') weiStr.remove(0,1);
  if (weiStr.length() <= 18) {
    String s = "0.";
    for (int i = 0; i < 18 - (int)weiStr.length(); i++) s += "0";
    s += weiStr;
    return s;
  }
  int p = weiStr.length() - 18;
  return weiStr.substring(0, p) + "." + weiStr.substring(p);
}

static inline String coinToWei(String coinStr) {
  int dot = coinStr.indexOf('.');
  String whole = (dot == -1) ? coinStr : coinStr.substring(0, dot);
  String frac  = (dot == -1) ? ""      : coinStr.substring(dot + 1);

  whole.trim(); frac.trim();
  if (whole.length() == 0) whole = "0";
  if (whole == "-") whole = "0";

  String w2;
  for (size_t i = 0; i < whole.length(); i++) if (isDigit(whole[i])) w2 += whole[i];
  if (w2.length() == 0) w2 = "0";

  String f2;
  for (size_t i = 0; i < frac.length(); i++) if (isDigit(frac[i])) f2 += frac[i];

  while (f2.length() < 18) f2 += "0";
  if (f2.length() > 18) f2 = f2.substring(0, 18);

  String wei = w2 + f2;
  while (wei.length() > 1 && wei[0] == '0') wei.remove(0,1);
  return wei;
}

// very simple decimal compare for non-negative integers (as strings)
static inline int cmpDecStr(String a, String b) {
  a.trim(); b.trim();
  while (a.length() > 1 && a[0] == '0') a.remove(0,1);
  while (b.length() > 1 && b[0] == '0') b.remove(0,1);
  if (a.length() < b.length()) return -1;
  if (a.length() > b.length()) return 1;
  int c = a.compareTo(b);
  if (c < 0) return -1;
  if (c > 0) return 1;
  return 0;
}

// a-b for non-negative decimal strings, assuming a>=b
static inline String subDecStr(String a, String b) {
  while (a.length() > 1 && a[0] == '0') a.remove(0,1);
  while (b.length() > 1 && b[0] == '0') b.remove(0,1);

  int ia = a.length()-1;
  int ib = b.length()-1;
  int carry = 0;
  String out = "";

  while (ia >= 0 || ib >= 0) {
    int da = (ia >= 0) ? (a[ia]-'0') : 0;
    int db = (ib >= 0) ? (b[ib]-'0') : 0;
    int v = da - db - carry;
    if (v < 0) { v += 10; carry = 1; } else carry = 0;
    out = char('0'+v) + out;
    ia--; ib--;
  }
  while (out.length() > 1 && out[0] == '0') out.remove(0,1);
  return out;
}

// ================= CRYPTO STORAGE (PBKDF2 + AES-GCM) =================
static inline bool ctEqual(const uint8_t* a, const uint8_t* b, size_t n) {
  uint8_t r = 0;
  for (size_t i = 0; i < n; i++) r |= (a[i] ^ b[i]);
  return r == 0;
}

static inline bool deriveFromPin(const String& pin, const uint8_t salt[16], uint8_t out32[32]) {
  const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  if (!info) return false;

  mbedtls_md_context_t ctx;
  mbedtls_md_init(&ctx);

  int rc = mbedtls_md_setup(&ctx, info, 1);
  if (rc != 0) { mbedtls_md_free(&ctx); return false; }

  rc = mbedtls_pkcs5_pbkdf2_hmac(
    &ctx,
    (const unsigned char*)pin.c_str(), pin.length(),
    salt, 16,
    PBKDF2_ITERS,
    32,
    out32
  );

  mbedtls_md_free(&ctx);
  return rc == 0;
}

// ---------- PIN / FAILS ----------
static inline bool smHasPin() {
  prefs.begin(NS, true);
  bool hasPin = prefs.getBool(K_HASPIN, false);
  prefs.end();
  return hasPin;
}

static inline int smGetFails() {
  prefs.begin(NS, true);
  int f = prefs.getInt(K_FAILS, 0);
  prefs.end();
  if (f < 0) f = 0;
  if (f > 99) f = 99;
  return f;
}

static inline void smSetFails(int f) {
  if (f < 0) f = 0;
  if (f > 99) f = 99;
  prefs.begin(NS, false);
  prefs.putInt(K_FAILS, f);
  prefs.end();
}

static inline void smResetFails() { smSetFails(0); }

static inline String smGetSavedAddress() {
  prefs.begin(NS, true);
  String a = prefs.getString(K_ADDR, "");
  prefs.end();
  return a;
}

static inline bool smHasSavedWallet() {
  prefs.begin(NS, true);
  size_t cLen = prefs.getBytesLength(K_CIPH);
  prefs.end();
  return cLen > 0;
}

static inline void smLoadSettings() {
  prefs.begin(NS, true);
  ethWei    = prefs.getString(K_ETHWEI, "0");
  bnbWei    = prefs.getString(K_BNBWEI, "0");
  priceETH  = prefs.getString(K_PETH,  "0");
  priceBNB  = prefs.getString(K_PBNB,  "0");
  prefs.end();
}

static inline void smSaveSettings() {
  prefs.begin(NS, false);
  prefs.putString(K_ETHWEI,  ethWei);
  prefs.putString(K_BNBWEI,  bnbWei);
  prefs.putString(K_PETH,    priceETH);
  prefs.putString(K_PBNB,    priceBNB);
  prefs.end();
}

static inline void resetBalancesOnNewWallet() {
  ethWei = "0"; bnbWei = "0";
  smSaveSettings();
}

static inline bool smVerifyPinOnly(const String& pinAttempt) {
  prefs.begin(NS, true);
  bool hasPin = prefs.getBool(K_HASPIN, false);
  if (!hasPin) { prefs.end(); return false; }

  uint8_t salt[16], storedPinh[32];
  if (prefs.getBytes(K_SALT, salt, 16) != 16 || prefs.getBytes(K_PINH, storedPinh, 32) != 32) {
    prefs.end(); return false;
  }
  prefs.end();

  uint8_t key[32];
  if (!deriveFromPin(pinAttempt, salt, key)) return false;

  bool ok = ctEqual(key, storedPinh, 32);
  memset(key, 0, sizeof(key));
  return ok;
}

static inline bool smFirstTimeSetup(const String& newPin) {
  if (newPin.length() < 4) return false;

  uint8_t salt[16]; esp_fill_random(salt, sizeof(salt));
  uint8_t pinh[32];
  if (!deriveFromPin(newPin, salt, pinh)) return false;

  prefs.begin(NS, false);
  bool ok = true;
  ok &= prefs.putBool(K_HASPIN, true);
  ok &= (prefs.putBytes(K_SALT, salt, 16) == 16);
  ok &= (prefs.putBytes(K_PINH, pinh, 32) == 32);
  ok &= prefs.putInt(K_FAILS, 0);
  prefs.end();

  memset(salt, 0, sizeof(salt));
  memset(pinh, 0, sizeof(pinh));

  smSaveSettings();
  return ok;
}

static inline bool smUnlock(const String& pinAttempt, String& outAddr, String& outPrivKey) {
  outAddr = "";
  outPrivKey = "";

  prefs.begin(NS, true);
  bool hasPin = prefs.getBool(K_HASPIN, false);
  if (!hasPin) { prefs.end(); return false; }

  uint8_t salt[16], storedPinh[32];
  if (prefs.getBytes(K_SALT, salt, 16) != 16 || prefs.getBytes(K_PINH, storedPinh, 32) != 32) {
    prefs.end(); return false;
  }

  uint8_t key[32];
  if (!deriveFromPin(pinAttempt, salt, key)) { prefs.end(); return false; }
  if (!ctEqual(key, storedPinh, 32)) {
    prefs.end(); memset(key,0,sizeof(key)); return false;
  }

  outAddr = prefs.getString(K_ADDR, "");

  size_t cLen = prefs.getBytesLength(K_CIPH);
  if (cLen == 0) {
    prefs.end();
    memset(key,0,sizeof(key));
    return true;
  }

  uint8_t iv[12], tag[16];
  if (prefs.getBytes(K_IV, iv, 12) != 12 || prefs.getBytes(K_TAG, tag, 16) != 16) {
    prefs.end(); memset(key,0,sizeof(key)); return false;
  }

  uint8_t* ciph = (uint8_t*)malloc(cLen);
  if (!ciph) { prefs.end(); memset(key,0,sizeof(key)); return false; }
  if (prefs.getBytes(K_CIPH, ciph, cLen) != cLen) {
    free(ciph); prefs.end(); memset(key,0,sizeof(key)); return false;
  }
  prefs.end();

  uint8_t* plain = (uint8_t*)malloc(cLen + 1);
  if (!plain) { free(ciph); memset(key,0,sizeof(key)); return false; }

  mbedtls_gcm_context gcm; mbedtls_gcm_init(&gcm);
  int rc = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256);
  if (rc == 0) {
    rc = mbedtls_gcm_auth_decrypt(&gcm, cLen, iv, 12, NULL, 0, tag, 16, ciph, plain);
  }
  mbedtls_gcm_free(&gcm);

  free(ciph);
  memset(key,0,sizeof(key));

  if (rc != 0) { memset(plain,0,cLen+1); free(plain); return false; }

  plain[cLen] = 0;
  outPrivKey = String((char*)plain);

  memset(plain,0,cLen+1);
  free(plain);
  return true;
}

static inline bool smSaveWallet(const String& address, const String& privKeyPlain, const String& pinForKeyDerive) {
  prefs.begin(NS, false);
  bool hasPin = prefs.getBool(K_HASPIN, false);
  if (!hasPin) { prefs.end(); return false; }

  uint8_t salt[16], storedPinh[32];
  if (prefs.getBytes(K_SALT, salt, 16) != 16 || prefs.getBytes(K_PINH, storedPinh, 32) != 32) {
    prefs.end(); return false;
  }

  uint8_t key[32];
  if (!deriveFromPin(pinForKeyDerive, salt, key)) { prefs.end(); return false; }
  if (!ctEqual(key, storedPinh, 32)) { prefs.end(); memset(key,0,sizeof(key)); return false; }

  const uint8_t* plain = (const uint8_t*)privKeyPlain.c_str();
  size_t pLen = privKeyPlain.length();

  uint8_t iv[12], tag[16];
  esp_fill_random(iv, sizeof(iv));

  uint8_t* ciph = (uint8_t*)malloc(pLen);
  if (!ciph) { prefs.end(); memset(key,0,sizeof(key)); return false; }

  mbedtls_gcm_context gcm; mbedtls_gcm_init(&gcm);
  int rc = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256);
  if (rc == 0) {
    rc = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, pLen, iv, 12, NULL, 0, plain, ciph, 16, tag);
  }
  mbedtls_gcm_free(&gcm);
  memset(key,0,sizeof(key));

  if (rc != 0) { memset(ciph,0,pLen); free(ciph); prefs.end(); return false; }

  prefs.putString(K_ADDR, address);
  bool ok = true;
  ok &= (prefs.putBytes(K_IV, iv, 12) == 12);
  ok &= (prefs.putBytes(K_TAG, tag, 16) == 16);
  ok &= (prefs.putBytes(K_CIPH, ciph, pLen) == pLen);

  memset(ciph,0,pLen);
  free(ciph);
  prefs.end();
  return ok;
}

static inline bool smChangePin(const String& oldPin, const String& newPin) {
  if (newPin.length() < 4) return false;
  if (!smVerifyPinOnly(oldPin)) return false;

  bool hasWallet = smHasSavedWallet();

  uint8_t newSalt[16]; esp_fill_random(newSalt, sizeof(newSalt));
  uint8_t newKey[32];
  if (!deriveFromPin(newPin, newSalt, newKey)) return false;

  prefs.begin(NS, false);
  bool ok = true;
  ok &= prefs.putBool(K_HASPIN, true);
  ok &= (prefs.putBytes(K_SALT, newSalt, 16) == 16);
  ok &= (prefs.putBytes(K_PINH, newKey, 32) == 32);
  ok &= prefs.putInt(K_FAILS, 0);
  prefs.end();

  if (ok && hasWallet) {
    if (!hasWalletRAM()) { memset(newKey,0,sizeof(newKey)); return false; }
    ok = smSaveWallet(walletAddress, privateKey, newPin);
  }

  memset(newSalt,0,sizeof(newSalt));
  memset(newKey,0,sizeof(newKey));
  return ok;
}

static inline void smStrongWipeAllNVS() {
  nvs_flash_erase();
  nvs_flash_init();
}

// ================= ADMIN PASSWORD (4-10 digits) =================
static inline bool smHasAdmin() {
  prefs.begin(NS, true);
  bool h = prefs.getBool(K_HASADM, false);
  prefs.end();
  return h;
}

static inline bool isDigitsLen(const String& s, int minL, int maxL) {
  if ((int)s.length() < minL || (int)s.length() > maxL) return false;
  for (size_t i = 0; i < s.length(); i++) if (!isDigit(s[i])) return false;
  return true;
}

static inline bool smAdminSetup(const String& pass) {
  if (!isDigitsLen(pass, 4, 10)) return false;
  if (smHasAdmin()) return false;

  uint8_t salt[16]; esp_fill_random(salt, sizeof(salt));
  uint8_t hash[32];
  if (!deriveFromPin(pass, salt, hash)) return false;

  prefs.begin(NS, false);
  bool ok = true;
  ok &= prefs.putBool(K_HASADM, true);
  ok &= (prefs.putBytes(K_ASALT, salt, 16) == 16);
  ok &= (prefs.putBytes(K_AHASH, hash, 32) == 32);
  prefs.end();

  memset(salt,0,sizeof(salt));
  memset(hash,0,sizeof(hash));
  return ok;
}

static inline bool smAdminVerify(const String& pass) {
  if (!isDigitsLen(pass, 4, 10)) return false;

  prefs.begin(NS, true);
  bool has = prefs.getBool(K_HASADM, false);
  if (!has) { prefs.end(); return false; }

  uint8_t salt[16], stored[32];
  if (prefs.getBytes(K_ASALT, salt, 16) != 16 || prefs.getBytes(K_AHASH, stored, 32) != 32) {
    prefs.end(); return false;
  }
  prefs.end();

  uint8_t out[32];
  if (!deriveFromPin(pass, salt, out)) return false;

  bool ok = ctEqual(out, stored, 32);
  memset(out,0,sizeof(out));
  return ok;
}

// Change admin: allow if old admin OK OR if recovery private key matches
static inline bool smAdminChange(const String& oldPass, const String& newPass, const String& recoveryPrivMaybe) {
  if (!isDigitsLen(newPass, 4, 10)) return false;
  bool allowed = false;

  if (smHasAdmin() && smAdminVerify(oldPass)) allowed = true;
  if (!allowed && recoveryPrivMaybe.length() > 0 && hasWalletRAM()) {
    if (recoveryPrivMaybe == privateKey) allowed = true;
  }
  if (!allowed) return false;

  uint8_t salt[16]; esp_fill_random(salt, sizeof(salt));
  uint8_t hash[32];
  if (!deriveFromPin(newPass, salt, hash)) return false;

  prefs.begin(NS, false);
  bool ok = true;
  ok &= prefs.putBool(K_HASADM, true);
  ok &= (prefs.putBytes(K_ASALT, salt, 16) == 16);
  ok &= (prefs.putBytes(K_AHASH, hash, 32) == 32);
  prefs.end();

  memset(salt,0,sizeof(salt));
  memset(hash,0,sizeof(hash));
  return ok;
}

// ================= WALLET GEN (secp256k1 + keccak) =================
static inline void performAccountGeneration(String &outPriv, String &outAddr) {
  uint8_t privKeyBytes[32];
  esp_fill_random(privKeyBytes, 32);

  mbedtls_ecp_group grp;
  mbedtls_ecp_point Q;
  mbedtls_mpi d;

  mbedtls_ecp_group_init(&grp);
  mbedtls_ecp_point_init(&Q);
  mbedtls_mpi_init(&d);

  mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256K1);
  mbedtls_mpi_read_binary(&d, privKeyBytes, 32);
  mbedtls_ecp_mul(&grp, &Q, &d, &grp.G, NULL, NULL);

  uint8_t pub_raw[65];
  size_t olen = 0;
  mbedtls_ecp_point_write_binary(&grp, &Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, pub_raw, 65);

  uint8_t hash[32];
  KeccakCore keccak;
  keccak.setCapacity(512);
  keccak.reset();
  keccak.update(&pub_raw[1], 64);
  keccak.pad(0x01);
  keccak.extract(hash, 32);

  outPriv = "0x";
  for (int i = 0; i < 32; i++) {
    if (privKeyBytes[i] < 0x10) outPriv += "0";
    outPriv += String(privKeyBytes[i], HEX);
  }

  outAddr = "0x";
  for (int i = 12; i < 32; i++) {
    if (hash[i] < 0x10) outAddr += "0";
    outAddr += String(hash[i], HEX);
  }

  mbedtls_ecp_group_free(&grp);
  mbedtls_ecp_point_free(&Q);
  mbedtls_mpi_free(&d);
}

// ================= WiFi settings persist =================
static inline void wifiLoad(String& ssid, String& pass) {
  prefs.begin(NS_WIFI, true);
  ssid = prefs.getString(K_WIFISSID, DEFAULT_SSID);
  pass = prefs.getString(K_WIFIPASS, DEFAULT_PASS);
  prefs.end();
}
static inline bool wifiSave(const String& ssid, const String& pass) {
  prefs.begin(NS_WIFI, false);
  prefs.putString(K_WIFISSID, ssid);
  prefs.putString(K_WIFIPASS, pass);
  prefs.end();
  return true;
}

// =================== HEX helpers ===================
static inline int hexNib(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
  if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
  return -1;
}

static inline bool hexToBytes(String hex, std::vector<uint8_t>& out) {
  out.clear();
  hex.trim();
  if (hex.startsWith("0x") || hex.startsWith("0X")) hex = hex.substring(2);
  if (hex.length() % 2 != 0) return false;
  out.reserve(hex.length() / 2);
  for (size_t i = 0; i < (size_t)hex.length(); i += 2) {
    int a = hexNib(hex[i]);
    int b = hexNib(hex[i+1]);
    if (a < 0 || b < 0) return false;
    out.push_back((uint8_t)((a << 4) | b));
  }
  return true;
}

static inline String bytesToHex(const uint8_t* b, size_t n, bool with0x=true) {
  static const char* he = "0123456789abcdef";
  String s;
  s.reserve((with0x?2:0) + n*2);
  if (with0x) s += "0x";
  for (size_t i=0;i<n;i++){
    s += he[(b[i]>>4)&0xF];
    s += he[b[i]&0xF];
  }
  return s;
}

static inline String vecToHex(const std::vector<uint8_t>& v, bool with0x=true) {
  if (v.empty()) return with0x ? "0x" : "";
  return bytesToHex(v.data(), v.size(), with0x);
}

// =================== Keccak256 ===================
static inline void keccak256(const uint8_t* data, size_t len, uint8_t out32[32]) {
  KeccakCore k;
  k.setCapacity(512);
  k.reset();
  k.update(data, len);
  k.pad(0x01);
  k.extract(out32, 32);
}

// =================== RLP (legacy tx) ===================
static inline void rlpAppendLen(std::vector<uint8_t>& out, size_t len, uint8_t offset) {
  if (len < 56) {
    out.push_back((uint8_t)(offset + len));
    return;
  }
  std::vector<uint8_t> tmp;
  while (len > 0) {
    tmp.push_back((uint8_t)(len & 0xFF));
    len >>= 8;
  }
  out.push_back((uint8_t)(offset + 55 + tmp.size()));
  for (int i = (int)tmp.size()-1; i >= 0; i--) out.push_back(tmp[i]);
}

static inline void rlpEncodeBytes(std::vector<uint8_t>& out, const uint8_t* data, size_t len) {
  if (len == 1 && data[0] < 0x80) {
    out.push_back(data[0]);
    return;
  }
  rlpAppendLen(out, len, 0x80);
  out.insert(out.end(), data, data + len);
}

static inline void rlpEncodeVector(std::vector<uint8_t>& out, const std::vector<uint8_t>& data) {
  if (data.empty()) {
    out.push_back(0x80);
    return;
  }
  rlpEncodeBytes(out, data.data(), data.size());
}

static inline void trimLeadingZeros(std::vector<uint8_t>& b) {
  while (b.size() > 1 && b[0] == 0x00) b.erase(b.begin());
  if (b.size()==1 && b[0]==0x00) b.clear(); // integer 0 => empty
}

static inline std::vector<uint8_t> u64ToBE(uint64_t v) {
  std::vector<uint8_t> b;
  if (v == 0) return b;
  for (int i = 7; i >= 0; i--) {
    uint8_t c = (uint8_t)((v >> (i*8)) & 0xFF);
    if (b.empty() && c == 0) continue;
    b.push_back(c);
  }
  return b;
}

static inline bool decToBE(const String& dec, std::vector<uint8_t>& out) {
  out.clear();
  String s = dec; s.trim();
  if (s.length()==0) { out.clear(); return true; }
  if (s[0] == '-') return false;

  mbedtls_mpi x;
  mbedtls_mpi_init(&x);
  int rc = mbedtls_mpi_read_string(&x, 10, s.c_str());
  if (rc != 0) { mbedtls_mpi_free(&x); return false; }

  size_t n = mbedtls_mpi_size(&x);
  if (n == 0) { mbedtls_mpi_free(&x); out.clear(); return true; }

  out.resize(n);
  rc = mbedtls_mpi_write_binary(&x, out.data(), out.size());
  mbedtls_mpi_free(&x);
  if (rc != 0) { out.clear(); return false; }

  trimLeadingZeros(out);
  return true;
}

static inline void rlpEncodeU64(std::vector<uint8_t>& out, uint64_t v) {
  std::vector<uint8_t> b = u64ToBE(v);
  rlpEncodeVector(out, b);
}

static inline bool rlpEncodeDec(std::vector<uint8_t>& out, const String& decStr) {
  std::vector<uint8_t> b;
  if (!decToBE(decStr, b)) return false;
  rlpEncodeVector(out, b);
  return true;
}

static inline void rlpEncodeList(std::vector<uint8_t>& out, const std::vector<uint8_t>& payload) {
  rlpAppendLen(out, payload.size(), 0xC0);
  out.insert(out.end(), payload.begin(), payload.end());
}

// =================== ECDSA sign + recover v (secp256k1) ===================
static inline bool pubFromPriv(const uint8_t priv[32], uint8_t pub65[65]) {
  mbedtls_ecp_group grp;
  mbedtls_ecp_point Q;
  mbedtls_mpi d;

  mbedtls_ecp_group_init(&grp);
  mbedtls_ecp_point_init(&Q);
  mbedtls_mpi_init(&d);

  bool ok = false;

  do {
    if (mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256K1) != 0) break;
    if (mbedtls_mpi_read_binary(&d, priv, 32) != 0) break;
    if (mbedtls_ecp_mul(&grp, &Q, &d, &grp.G, NULL, NULL) != 0) break;

    size_t olen = 0;
    if (mbedtls_ecp_point_write_binary(&grp, &Q, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                       &olen, pub65, 65) != 0) break;
    if (olen != 65) break;

    ok = true;
  } while (0);

  mbedtls_ecp_group_free(&grp);
  mbedtls_ecp_point_free(&Q);
  mbedtls_mpi_free(&d);

  return ok;
}

// modular sqrt for secp256k1 prime p (p % 4 == 3): sqrt(a) = a^((p+1)/4) mod p
static inline int modSqrtP(mbedtls_mpi* y, const mbedtls_mpi* a, const mbedtls_mpi* p) {
  mbedtls_mpi exp;
  mbedtls_mpi_init(&exp);

  mbedtls_mpi tmp;
  mbedtls_mpi_init(&tmp);
  int rc = mbedtls_mpi_copy(&tmp, p);
  if (rc != 0) goto out;
  rc = mbedtls_mpi_add_int(&tmp, &tmp, 1);
  if (rc != 0) goto out;
  rc = mbedtls_mpi_shift_r(&tmp, 2);
  if (rc != 0) goto out;

  rc = mbedtls_mpi_copy(&exp, &tmp);
  if (rc != 0) goto out;

  rc = mbedtls_mpi_exp_mod(y, a, &exp, p, NULL);

out:
  mbedtls_mpi_free(&exp);
  mbedtls_mpi_free(&tmp);
  return rc;
}

static inline bool recoverRecId(const uint8_t hash32[32], const mbedtls_mpi* r, const mbedtls_mpi* s,
                                const uint8_t expectedPub65[65], int& outRecId,
                                mbedtls_ecp_group* grp) {
  mbedtls_mpi e; mbedtls_mpi_init(&e);
  if (mbedtls_mpi_read_binary(&e, hash32, 32) != 0) { mbedtls_mpi_free(&e); return false; }
  mbedtls_mpi_mod_mpi(&e, &e, &grp->N);

  mbedtls_mpi rInv; mbedtls_mpi_init(&rInv);
  if (mbedtls_mpi_inv_mod(&rInv, r, &grp->N) != 0) { mbedtls_mpi_free(&e); mbedtls_mpi_free(&rInv); return false; }

  mbedtls_mpi eNeg; mbedtls_mpi_init(&eNeg);
  mbedtls_mpi_copy(&eNeg, &e);
  mbedtls_mpi_sub_mpi(&eNeg, &grp->N, &eNeg);
  mbedtls_mpi_mod_mpi(&eNeg, &eNeg, &grp->N);

  for (int recid=0; recid<4; recid++) {
    int j = recid / 2;
    int ybit = recid % 2;

    mbedtls_mpi x; mbedtls_mpi_init(&x);
    mbedtls_mpi_copy(&x, r);
    if (j == 1) mbedtls_mpi_add_mpi(&x, &x, &grp->N);

    if (mbedtls_mpi_cmp_mpi(&x, &grp->P) >= 0) { mbedtls_mpi_free(&x); continue; }

    mbedtls_mpi alpha; mbedtls_mpi_init(&alpha);
    mbedtls_mpi t; mbedtls_mpi_init(&t);

    mbedtls_mpi_mul_mpi(&t, &x, &x);
    mbedtls_mpi_mod_mpi(&t, &t, &grp->P);

    mbedtls_mpi_mul_mpi(&alpha, &t, &x);
    mbedtls_mpi_mod_mpi(&alpha, &alpha, &grp->P);

    mbedtls_mpi_add_int(&alpha, &alpha, 7);
    mbedtls_mpi_mod_mpi(&alpha, &alpha, &grp->P);

    mbedtls_mpi y; mbedtls_mpi_init(&y);
    if (modSqrtP(&y, &alpha, &grp->P) != 0) {
      mbedtls_mpi_free(&x); mbedtls_mpi_free(&alpha); mbedtls_mpi_free(&t); mbedtls_mpi_free(&y);
      continue;
    }

    int yIsOdd = mbedtls_mpi_get_bit(&y, 0);
    if (yIsOdd != ybit) {
      mbedtls_mpi_sub_mpi(&y, &grp->P, &y);
      mbedtls_mpi_mod_mpi(&y, &y, &grp->P);
    }

    mbedtls_ecp_point R;
    mbedtls_ecp_point_init(&R);
    mbedtls_mpi_copy(&R.X, &x);
    mbedtls_mpi_copy(&R.Y, &y);
    mbedtls_mpi_lset(&R.Z, 1);

    mbedtls_ecp_point X;
    mbedtls_ecp_point_init(&X);
    int rc = mbedtls_ecp_muladd(grp, &X, s, &R, &eNeg, &grp->G);
    if (rc != 0) {
      mbedtls_ecp_point_free(&R);
      mbedtls_ecp_point_free(&X);
      mbedtls_mpi_free(&x); mbedtls_mpi_free(&alpha); mbedtls_mpi_free(&t); mbedtls_mpi_free(&y);
      continue;
    }

    mbedtls_ecp_point Q;
    mbedtls_ecp_point_init(&Q);
    rc = mbedtls_ecp_mul(grp, &Q, &rInv, &X, NULL, NULL);
    if (rc != 0) {
      mbedtls_ecp_point_free(&R);
      mbedtls_ecp_point_free(&X);
      mbedtls_ecp_point_free(&Q);
      mbedtls_mpi_free(&x); mbedtls_mpi_free(&alpha); mbedtls_mpi_free(&t); mbedtls_mpi_free(&y);
      continue;
    }

    uint8_t pub65[65]; size_t olen=0;
    rc = mbedtls_ecp_point_write_binary(grp, &Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, pub65, 65);
    bool match = (rc==0 && olen==65 && memcmp(pub65, expectedPub65, 65) == 0);

    mbedtls_ecp_point_free(&R);
    mbedtls_ecp_point_free(&X);
    mbedtls_ecp_point_free(&Q);

    mbedtls_mpi_free(&x); mbedtls_mpi_free(&alpha); mbedtls_mpi_free(&t); mbedtls_mpi_free(&y);

    if (match) {
      outRecId = recid;
      mbedtls_mpi_free(&e);
      mbedtls_mpi_free(&rInv);
      mbedtls_mpi_free(&eNeg);
      return true;
    }
  }

  mbedtls_mpi_free(&e);
  mbedtls_mpi_free(&rInv);
  mbedtls_mpi_free(&eNeg);
  return false;
}

static inline bool signHashRecoverable(const uint8_t hash32[32], const uint8_t privKeyBytes[32],
                                      mbedtls_mpi* r, mbedtls_mpi* s, int& recidOut) {
  mbedtls_ecp_group grp;
  mbedtls_ecp_group_init(&grp);
  if (mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256K1) != 0) { mbedtls_ecp_group_free(&grp); return false; }

  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr;
  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&ctr);
  const char* pers = "sm_sign";
  if (mbedtls_ctr_drbg_seed(&ctr, mbedtls_entropy_func, &entropy, (const unsigned char*)pers, strlen(pers)) != 0) {
    mbedtls_ctr_drbg_free(&ctr); mbedtls_entropy_free(&entropy); mbedtls_ecp_group_free(&grp);
    return false;
  }

  mbedtls_mpi d; mbedtls_mpi_init(&d);
  if (mbedtls_mpi_read_binary(&d, privKeyBytes, 32) != 0) {
    mbedtls_mpi_free(&d);
    mbedtls_ctr_drbg_free(&ctr); mbedtls_entropy_free(&entropy); mbedtls_ecp_group_free(&grp);
    return false;
  }

  if (mbedtls_ecdsa_sign(&grp, r, s, &d, (const unsigned char*)hash32, 32,
                        mbedtls_ctr_drbg_random, &ctr) != 0) {
    mbedtls_mpi_free(&d);
    mbedtls_ctr_drbg_free(&ctr); mbedtls_entropy_free(&entropy); mbedtls_ecp_group_free(&grp);
    return false;
  }

  uint8_t expPub[65];
  if (!pubFromPriv(privKeyBytes, expPub)) {
    mbedtls_mpi_free(&d);
    mbedtls_ctr_drbg_free(&ctr); mbedtls_entropy_free(&entropy); mbedtls_ecp_group_free(&grp);
    return false;
  }

  mbedtls_mpi halfN; mbedtls_mpi_init(&halfN);
  mbedtls_mpi_copy(&halfN, &grp.N);
  mbedtls_mpi_shift_r(&halfN, 1);
  bool flipped = false;
  if (mbedtls_mpi_cmp_mpi(s, &halfN) > 0) {
    mbedtls_mpi tmp; mbedtls_mpi_init(&tmp);
    mbedtls_mpi_sub_mpi(&tmp, &grp.N, s);
    mbedtls_mpi_copy(s, &tmp);
    mbedtls_mpi_free(&tmp);
    flipped = true;
  }
  mbedtls_mpi_free(&halfN);

  int recid = -1;
  if (!recoverRecId(hash32, r, s, expPub, recid, &grp)) {
    mbedtls_mpi_free(&d);
    mbedtls_ctr_drbg_free(&ctr); mbedtls_entropy_free(&entropy); mbedtls_ecp_group_free(&grp);
    return false;
  }

  if (flipped) recid ^= 1;
  recidOut = recid;

  mbedtls_mpi_free(&d);
  mbedtls_ctr_drbg_free(&ctr);
  mbedtls_entropy_free(&entropy);
  mbedtls_ecp_group_free(&grp);
  return true;
}

static inline bool buildSignedTxEIP155(const String& toHex, const String& valueWeiDec,
                                      uint64_t nonce, uint64_t gasPriceGwei, uint64_t gasLimit,
                                      uint32_t chainId,
                                      const String& privKeyHex,
                                      String& outRawTxHex, String& outTxHashHex, String& outErr) {
  outErr = "";
  outRawTxHex = "";
  outTxHashHex = "";

  const uint64_t ONE_GWEI = 1000000000ULL;
  if (gasPriceGwei > (UINT64_MAX / ONE_GWEI)) { outErr="Gas price too big"; return false; }
  uint64_t gasPriceWei = gasPriceGwei * ONE_GWEI;

  std::vector<uint8_t> toBytes;
  if (!hexToBytes(toHex, toBytes) || toBytes.size() != 20) { outErr="Bad TO address"; return false; }

  std::vector<uint8_t> pkb;
  if (!hexToBytes(privKeyHex, pkb) || pkb.size() != 32) { outErr="Bad private key"; return false; }

  std::vector<uint8_t> payload;
  payload.reserve(256);

  rlpEncodeU64(payload, nonce);
  rlpEncodeU64(payload, gasPriceWei);
  rlpEncodeU64(payload, gasLimit);
  rlpEncodeBytes(payload, toBytes.data(), 20);
  if (!rlpEncodeDec(payload, valueWeiDec)) { outErr="Bad valueWei"; return false; }
  payload.push_back(0x80); // data empty
  rlpEncodeU64(payload, chainId);
  payload.push_back(0x80);
  payload.push_back(0x80);

  std::vector<uint8_t> unsignedRlp;
  unsignedRlp.reserve(payload.size() + 16);
  rlpEncodeList(unsignedRlp, payload);

  uint8_t sighash[32];
  keccak256(unsignedRlp.data(), unsignedRlp.size(), sighash);

  mbedtls_mpi r, s;
  mbedtls_mpi_init(&r);
  mbedtls_mpi_init(&s);
  int recid = 0;

  if (!signHashRecoverable(sighash, pkb.data(), &r, &s, recid)) {
    mbedtls_mpi_free(&r); mbedtls_mpi_free(&s);
    outErr="Sign failed";
    return false;
  }

  uint64_t v = (uint64_t)recid + 35ULL + 2ULL*(uint64_t)chainId;

  size_t rlen = mbedtls_mpi_size(&r);
  size_t slen = mbedtls_mpi_size(&s);
  std::vector<uint8_t> rb(rlen), sb(slen);
  if (rlen) mbedtls_mpi_write_binary(&r, rb.data(), rb.size());
  if (slen) mbedtls_mpi_write_binary(&s, sb.data(), sb.size());
  trimLeadingZeros(rb);
  trimLeadingZeros(sb);

  mbedtls_mpi_free(&r);
  mbedtls_mpi_free(&s);

  std::vector<uint8_t> sp;
  sp.reserve(256);

  rlpEncodeU64(sp, nonce);
  rlpEncodeU64(sp, gasPriceWei);
  rlpEncodeU64(sp, gasLimit);
  rlpEncodeBytes(sp, toBytes.data(), 20);
  if (!rlpEncodeDec(sp, valueWeiDec)) { outErr="Bad valueWei"; return false; }
  sp.push_back(0x80); // data empty

  rlpEncodeU64(sp, v);
  rlpEncodeVector(sp, rb);
  rlpEncodeVector(sp, sb);

  std::vector<uint8_t> signedRlp;
  signedRlp.reserve(sp.size() + 16);
  rlpEncodeList(signedRlp, sp);

  outRawTxHex = vecToHex(signedRlp, true);

  uint8_t txh[32];
  keccak256(signedRlp.data(), signedRlp.size(), txh);
  outTxHashHex = bytesToHex(txh, 32, true);

  return true;
}

// =================== TX HISTORY (last 3) — FIELD STORAGE (FIXED) ===================
struct TxKeys {
  const char* c;  const char* to; const char* a;
  const char* n;  const char* g;  const char* l;
  const char* id; const char* h;  const char* r;
  const char* s;  const char* t;
};
// ===== TX FIELD KEY STRUCT =====


static inline TxKeys txKeys(int slot){
  if(slot==0) return {K_T0_C,K_T0_TO,K_T0_A,K_T0_N,K_T0_G,K_T0_L,K_T0_ID,K_T0_H,K_T0_R,K_T0_S,K_T0_T};
  if(slot==1) return {K_T1_C,K_T1_TO,K_T1_A,K_T1_N,K_T1_G,K_T1_L,K_T1_ID,K_T1_H,K_T1_R,K_T1_S,K_T1_T};
  return         {K_T2_C,K_T2_TO,K_T2_A,K_T2_N,K_T2_G,K_T2_L,K_T2_ID,K_T2_H,K_T2_R,K_T2_S,K_T2_T};
}

static inline String txToJson(const TxRecord& t) {
  String s="{";
  s += "\"coin\":\""+jsonEscape(t.coin)+"\",";
  s += "\"to\":\""+jsonEscape(t.to)+"\",";
  s += "\"amount\":\""+jsonEscape(t.amountCoin)+"\",";
  s += "\"nonce\":"+String(t.nonce)+",";
  s += "\"gasGwei\":"+String(t.gasGwei)+",";
  s += "\"gasLimit\":"+String(t.gasLimit)+",";
  s += "\"chainId\":"+String(t.chainId)+",";
  s += "\"txHash\":\""+jsonEscape(t.txHash)+"\",";
  s += "\"rawTx\":\""+jsonEscape(t.rawTx)+"\",";
  s += "\"status\":\""+jsonEscape(t.status)+"\",";
  s += "\"tsec\":"+String(t.tsec);
  s += "}";
  return s;
}

static inline void txClearSlot(int slot){
  TxKeys k = txKeys(slot);
  prefs.remove(k.c);  prefs.remove(k.to); prefs.remove(k.a);
  prefs.remove(k.n);  prefs.remove(k.g);  prefs.remove(k.l);
  prefs.remove(k.id); prefs.remove(k.h);  prefs.remove(k.r);
  prefs.remove(k.s);  prefs.remove(k.t);
}

static inline void txWriteSlot(int slot, const TxRecord& t){
  TxKeys k = txKeys(slot);
  prefs.putString(k.c,  t.coin);
  prefs.putString(k.to, t.to);
  prefs.putString(k.a,  t.amountCoin);
  prefs.putULong64(k.n, t.nonce);
  prefs.putULong64(k.g, t.gasGwei);
  prefs.putULong64(k.l, t.gasLimit);
  prefs.putUInt(k.id,   t.chainId);
  prefs.putString(k.h,  t.txHash);
  prefs.putString(k.r,  t.rawTx);
  prefs.putString(k.s,  t.status);
  prefs.putUInt(k.t,    t.tsec);
}

static inline bool txReadSlot(int slot, TxRecord& out){
  TxKeys k = txKeys(slot);
  out = TxRecord();
  out.coin = prefs.getString(k.c, "");
  out.to   = prefs.getString(k.to, "");
  out.amountCoin = prefs.getString(k.a, "");
  out.nonce    = prefs.getULong64(k.n, 0);
  out.gasGwei   = prefs.getULong64(k.g, 0);
  out.gasLimit  = prefs.getULong64(k.l, 21000);
  out.chainId   = prefs.getUInt(k.id, 56);
  out.txHash    = prefs.getString(k.h, "");
  out.rawTx     = prefs.getString(k.r, "");
  out.status    = prefs.getString(k.s, "");
  out.tsec      = prefs.getUInt(k.t, 0);
  return out.txHash.length() > 0;
}

static inline void txCopySlot(int from, int to){
  TxRecord tmp;
  if(txReadSlot(from, tmp)) txWriteSlot(to, tmp);
  else txClearSlot(to);
}

// Push new tx: slot0->slot1, slot1->slot2, new->slot0
static inline void smPushTx(const TxRecord& t) {
  prefs.begin(NS, false);
  txCopySlot(1,2);
  txCopySlot(0,1);
  txWriteSlot(0,t);
  prefs.end();
}

static inline String smGetTxArrayJson() {
  prefs.begin(NS, true);
  TxRecord t0,t1,t2;
  bool h0 = txReadSlot(0, t0);
  bool h1 = txReadSlot(1, t1);
  bool h2 = txReadSlot(2, t2);
  prefs.end();

  String out="[";
  bool first=true;
  if(h0){ out += txToJson(t0); first=false; }
  if(h1){ if(!first) out += ","; out += txToJson(t1); first=false; }
  if(h2){ if(!first) out += ","; out += txToJson(t2); }
  out += "]";
  return out;
}

static inline bool txFindByHash(const String& txHash, TxRecord& out, int& slotOut){
  prefs.begin(NS, true);
  TxRecord t;
  for(int i=0;i<3;i++){
    if(txReadSlot(i, t) && t.txHash == txHash){
      prefs.end();
      out = t;
      slotOut = i;
      return true;
    }
  }
  prefs.end();
  return false;
}

static inline bool smSetTxStatusByHash(const String& txHash, const String& newStatus) {
  bool changed = false;
  prefs.begin(NS, false);

  TxRecord t;
  for(int i=0;i<3;i++){
    if(txReadSlot(i, t) && t.txHash == txHash){
      TxKeys k = txKeys(i);
      prefs.putString(k.s, newStatus);
      changed = true;
    }
  }

  prefs.end();
  return changed;
}

// =================== PRICE HISTORY (last 5) ===================
static inline String makePriceSnapJson(float totalUSD) {
  uint32_t t = upSeconds();
  char tot[32];
  dtostrf(totalUSD, 0, 2, tot);

  String s="{";
  s += "\"tsec\":"+String(t)+",";
  s += "\"pETH\":\""+jsonEscape(priceETH)+"\",";
  s += "\"pBNB\":\""+jsonEscape(priceBNB)+"\",";
  s += "\"total\":\""+String(tot)+"\"";
  s += "}";
  return s;
}

static inline void smPushPriceSnap(float totalUSD) {
  prefs.begin(NS, false);
  String o0 = prefs.getString(K_PH0, "");
  String o1 = prefs.getString(K_PH1, "");
  String o2 = prefs.getString(K_PH2, "");
  String o3 = prefs.getString(K_PH3, "");
  prefs.putString(K_PH4, o3);
  prefs.putString(K_PH3, o2);
  prefs.putString(K_PH2, o1);
  prefs.putString(K_PH1, o0);
  prefs.putString(K_PH0, makePriceSnapJson(totalUSD));
  prefs.end();
}

static inline String smGetPriceHistoryJson() {
  prefs.begin(NS, true);
  String a0 = prefs.getString(K_PH0, "");
  String a1 = prefs.getString(K_PH1, "");
  String a2 = prefs.getString(K_PH2, "");
  String a3 = prefs.getString(K_PH3, "");
  String a4 = prefs.getString(K_PH4, "");
  prefs.end();

  String out="[";
  bool first=true;
  if (a0.length()) { out += a0; first=false; }
  if (a1.length()) { if(!first) out += ","; out += a1; first=false; }
  if (a2.length()) { if(!first) out += ","; out += a2; first=false; }
  if (a3.length()) { if(!first) out += ","; out += a3; first=false; }
  if (a4.length()) { if(!first) out += ","; out += a4; }
  out += "]";
  return out;
}

// =================== TOTAL USD + % CHANGE ===================
static inline float calcTotalUSD() {
  String eth = weiToCoin(ethWei);
  String bnb = weiToCoin(bnbWei);
  float e = eth.toFloat() * priceETH.toFloat();
  float b = bnb.toFloat() * priceBNB.toFloat();
  return e + b;
}

static inline String getLastTotalStr() {
  prefs.begin(NS, true);
  String s = prefs.getString(K_LASTTOTAL, "0");
  prefs.end();
  return s;
}

static inline void setLastTotalStr(const String& s) {
  prefs.begin(NS, false);
  prefs.putString(K_LASTTOTAL, s);
  prefs.end();
}

static inline void format2(float v, char* out, size_t n) {
  char tmp[32];
  dtostrf(v, 0, 2, tmp);
  strncpy(out, tmp, n);
  out[n-1] = 0;
}

// ========================= WEB UI PAGE =========================
const char PAGE[] PROGMEM = R"HTML(
<!doctype html><html><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Singularity Money</title>
<style>
  :root{
    --bg:#0b0f14;--card:#0f1723;--line:#203047;--text:#e6edf3;--mut:#9aa6b2;
    --pri:#1f6feb;--ok:#7ee787;--bad:#ff7b72;
  }
  *{box-sizing:border-box}
  body{margin:0;font-family:system-ui;background:var(--bg);color:var(--text)}
  header{padding:10px 12px;background:#0e1520;border-bottom:1px solid var(--line)}
  main{max-width:900px;margin:0 auto;padding:12px}
  .card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:12px;margin:10px 0}
  h2{margin:0 0 8px 0;font-size:22px}
  .small{color:var(--mut);font-size:12px}
  .row{display:flex;gap:8px;flex-wrap:wrap}
  input,button,textarea,select{border-radius:10px;border:1px solid var(--line);background:#0b0f14;color:var(--text);padding:9px 10px;font-size:14px}
  textarea{width:100%;min-height:120px}
  select{min-width:140px}
  button{background:var(--pri);border:none;font-weight:900;padding:9px 12px;display:inline-flex;align-items:center;gap:8px}
  button.ghost{background:transparent;border:1px solid var(--line);font-weight:650}
  button.danger{background:#b42318}
  button:disabled{opacity:.55}
  code{display:block;padding:10px;border:1px solid var(--line);border-radius:10px;background:#0b0f14;overflow:auto}
  .ok{color:var(--ok)} .bad{color:var(--bad)}
  .ico{width:14px;height:14px;display:inline-block;flex:0 0 auto}
  .modalBack{position:fixed;inset:0;background:rgba(0,0,0,.55);display:none;align-items:center;justify-content:center;padding:12px;z-index:5000}
  .modal{width:min(780px,100%);background:var(--card);border:1px solid var(--line);border-radius:12px;padding:12px;max-height:86vh;display:flex;flex-direction:column}
  .modal h3{margin:0 0 8px 0}
  .modalBody{overflow:auto;max-height:76vh;padding-right:4px}
  .loadingBack{position:fixed;inset:0;background:rgba(0,0,0,.60);display:none;align-items:center;justify-content:center;padding:12px;z-index:9999}
  .loadingBox{width:min(420px,100%);background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px}
  .spinner{width:18px;height:18px;border:2px solid rgba(255,255,255,.25);border-top-color:#fff;border-radius:50%;display:inline-block;animation:spin .8s linear infinite;vertical-align:-3px;margin-right:10px}
  @keyframes spin{to{transform:rotate(360deg)}}
</style>
</head>
<body>
<header>
  <div style="display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap">
    <div>
      <b>Singularity Money</b>
      <div class="small">Offline AP • Cold-sign prototype</div>
    </div>
    <div id="topStatus" class="small"></div>
  </div>
</header>

<main>
  <div class="card" id="authCard"></div>

  <div class="card" id="homeCard" style="display:none">
    <h2>Home</h2>
    <div class="small" id="homeLine">Locked</div>

    <div style="margin-top:10px">
      <div>Saved wallet: <b id="savedWallet" class="bad">NO</b></div>
      <div>Address: <b id="addrShort" class="bad">(none)</b></div>
      <div style="margin-top:8px">
        Total Balance (USD): <b id="totalUSD" class="bad">$0.00</b>
        <span id="pctSpan" class="small" style="margin-left:8px"></span>
      </div>
    </div>

    <div class="row" style="margin-top:12px">
      <button id="btnCreate"><span class="ico">➕</span>Create</button>
      <button id="btnImport"><span class="ico">📥</span>Import</button>
      <button id="btnReceive"><span class="ico">📩</span>Receive</button>
      <button id="btnBalance"><span class="ico">💰</span>Balance</button>
      <button id="btnSend"><span class="ico">✍️</span>Send (Offline)</button>
      <button id="btnTx"><span class="ico">🧾</span>Tx History</button>
      <button id="btnSettings" class="ghost"><span class="ico">⚙️</span>Settings</button>
      <button id="btnLock" class="ghost"><span class="ico">🔒</span>Lock</button>
    </div>

    <div id="panel" style="margin-top:12px"></div>
  </div>
</main>

<div class="modalBack" id="modalBack">
  <div class="modal">
    <h3 id="modalTitle">Info</h3>
    <div id="modalBody" class="modalBody"></div>
    <div class="row" style="margin-top:12px;justify-content:flex-end">
      <button class="ghost" id="modalClose">Close</button>
    </div>
  </div>
</div>

<div class="loadingBack" id="loadingBack">
  <div class="loadingBox">
    <div style="font-weight:900;margin-bottom:6px" id="loadingTitle">Working…</div>
    <div class="small" id="loadingText">Please wait.</div>
    <div style="margin-top:12px">
      <span class="spinner"></span><span class="small">Do not disconnect power.</span>
    </div>
  </div>
</div>

<script>
function applyTheme(name){
  const root = document.documentElement;
  if(name==="pink"){
    root.style.setProperty("--pri","#ff4da6");
    root.style.setProperty("--card","#191025");
    root.style.setProperty("--line","#3b1d3a");
  } else if(name==="green"){
    root.style.setProperty("--pri","#22c55e");
    root.style.setProperty("--card","#0f1a14");
    root.style.setProperty("--line","#1f3a2b");
  } else if(name==="yellow"){
    root.style.setProperty("--pri","#facc15");
    root.style.setProperty("--card","#1a160f");
    root.style.setProperty("--line","#3a2f1f");
  } else {
    root.style.setProperty("--pri","#1f6feb");
    root.style.setProperty("--card","#0f1723");
    root.style.setProperty("--line","#203047");
  }
  localStorage.setItem("sm_theme", name);
}
applyTheme(localStorage.getItem("sm_theme") || "default");

let T = "";
const $ = (id)=>document.getElementById(id);

async function api(path, data=null){
  const opt = data ? {method:"POST", headers:{"Content-Type":"application/x-www-form-urlencoded"}, body:new URLSearchParams(data)} : {};
  const tokenPart = "t=" + encodeURIComponent(T || "");
  const url = path + (path.includes("?")?"&":"?") + tokenPart;
  const r = await fetch(url, opt);
  return await r.json();
}

function openModal(title, bodyHtml){
  $("modalTitle").textContent = title;
  $("modalBody").innerHTML = bodyHtml;
  $("modalBack").style.display = "flex";
}
function closeModal(){ $("modalBack").style.display="none"; }
$("modalClose").onclick = closeModal;
$("modalBack").onclick = (e)=>{ if(e.target.id==="modalBack") closeModal(); };

function setBusy(on, title="Working…", text="Please wait…"){
  if(on){
    $("loadingTitle").textContent = title;
    $("loadingText").textContent = text;
    $("loadingBack").style.display = "flex";
  } else {
    $("loadingBack").style.display = "none";
  }
}
function disableAll(dis){
  document.querySelectorAll("button,input,textarea,select").forEach(x => x.disabled = dis);
}

async function refreshHome(){
  const st = await api("/api/status");
  $("savedWallet").textContent = st.hasSavedWallet ? "YES" : "NO";
  $("savedWallet").className = st.hasSavedWallet ? "ok" : "bad";
  $("addrShort").textContent = st.savedAddr ? st.short : "(none)";
  $("addrShort").className = st.savedAddr ? "ok" : "bad";

  const sum = await api("/api/summary");
  if(sum.ok){
    $("totalUSD").textContent = "$" + sum.totalUSD;
    $("totalUSD").className = "ok";
    if(sum.pct !== ""){
      const pct = parseFloat(sum.pct);
      if(!isNaN(pct)){
        $("pctSpan").textContent = (pct>=0?("+"):("")) + pct.toFixed(2) + "%";
        $("pctSpan").className = "small " + (pct>=0 ? "ok" : "bad");
      } else $("pctSpan").textContent="";
    } else $("pctSpan").textContent="";
  } else {
    $("totalUSD").textContent = "$0.00";
    $("totalUSD").className = "bad";
    $("pctSpan").textContent="";
  }
  return st;
}

async function boot(){
  const st = await fetch("/api/status").then(r=>r.json());

  if(!st.pinSet){
    $("authCard").innerHTML = `
      <h2>First Setup</h2>
      <div class="small">Set PIN (4+ digits). Wallet stored encrypted in flash.</div>
      <input id="pinNew" type="password" placeholder="New PIN">
      <button id="btnSetPin" style="margin-top:10px">Set PIN</button>
    `;
    $("btnSetPin").onclick = async ()=>{
      const pin = ($("pinNew").value || "");
      try{
        setBusy(true,"Setting PIN…","Saving secure verifier.");
        disableAll(true);
        const r = await api("/api/setup",{pin});
        if(!r.ok) throw new Error(r.err || "Setup failed");
        openModal("Done ✅","<div class='small'>PIN set. Reloading…</div>");
        setTimeout(()=>location.reload(), 600);
      } catch(e){
        alert(e.message||"Failed");
      } finally {
        disableAll(false);
        setBusy(false);
      }
    };
    return;
  }

  $("authCard").innerHTML = `
    <h2>Unlock</h2>
    <div class="small" id="triesLine">Wrong tries left: <b>${st.triesLeft}</b> (3 wrong = wipe)</div>
    <input id="pinIn" type="password" placeholder="Enter PIN">
    <button id="btnUnlock" style="margin-top:10px">Unlock</button>
  `;

  $("btnUnlock").onclick = async ()=>{
    const pin = ($("pinIn").value || "");
    try{
      setBusy(true,"Unlocking…","Deriving key & decrypting wallet.");
      disableAll(true);
      const r = await api("/api/login",{pin});
      if(!r.ok){
        if(r.wiped){ alert("3 wrong attempts. Device wiped."); location.reload(); return; }
        throw new Error(r.err || "Wrong PIN");
      }
      T = r.t;

      $("authCard").style.display="none";
      $("homeCard").style.display="block";
      $("homeLine").textContent="OFFLINE AP mode • Unlocked";
      $("topStatus").textContent="Unlocked";

      await refreshHome();
      bindButtons();
      openModal("Welcome ✅","<div class='small'>Unlocked.</div>");
    } catch(e){
      alert(e.message||"Failed");
      const st2 = await fetch("/api/status").then(x=>x.json());
      $("triesLine").innerHTML = `Wrong tries left: <b>${st2.triesLeft}</b> (3 wrong = wipe)`;
    } finally {
      disableAll(false);
      setBusy(false);
    }
  };
}

function bindButtons(){
  $("btnLock").onclick = async ()=>{
    try{
      setBusy(true,"Locking…","Clearing session.");
      disableAll(true);
      await api("/api/logout");
      T=""; location.reload();
    } finally {
      disableAll(false);
      setBusy(false);
    }
  };

  async function confirmOverwriteIfNeeded(){
    const st = await api("/api/status");
    if(!st.hasSavedWallet) return {ok:true, pin:"", ap:"", yes:""};
    const yes = prompt("Wallet exists. Type YES to overwrite (old wallet will be erased)");
    if((yes||"").trim().toUpperCase() !== "YES") return {ok:false};
    const pin = prompt("Enter PIN to confirm overwrite");
    if(!pin) return {ok:false};
    const ap = prompt("Enter Admin PIN (required to overwrite)");
    if(!ap) return {ok:false};
    return {ok:true, pin, ap, yes:"YES"};
  }

  $("btnCreate").onclick = async ()=>{
    try{
      setBusy(true,"Creating wallet…","Generating keys & saving encrypted data.");
      disableAll(true);

      const confirm = await confirmOverwriteIfNeeded();
      if(!confirm.ok){ setBusy(false); disableAll(false); return; }

      const r = await api("/api/create", confirm.yes ? {pin:confirm.pin, ap:confirm.ap, yes:confirm.yes} : null);
      if(!r.ok) throw new Error(r.err || "Create failed");
      await refreshHome();
      $("panel").innerHTML = `<div class="small ok">✅ Wallet created & saved. Balances reset.</div>`;
      openModal("Done ✅","<div class='small'>Wallet created. Balances cleared.</div>");
    } catch(e){
      alert(e.message||"Failed");
    } finally {
      disableAll(false);
      setBusy(false);
    }
  };

  $("btnImport").onclick = async ()=>{
    const addr = prompt("Enter address (0x...)");
    const pk   = prompt("Enter private key (0x...)");
    if(!addr || !pk) return;

    try{
      setBusy(true,"Importing…","Saving encrypted wallet to flash.");
      disableAll(true);

      const confirm = await confirmOverwriteIfNeeded();
      if(!confirm.ok){ setBusy(false); disableAll(false); return; }

      const r = await api("/api/import",{addr,pk,pin:confirm.pin,ap:confirm.ap,yes:confirm.yes});
      if(!r.ok) throw new Error(r.err || "Import failed");
      await refreshHome();
      $("panel").innerHTML = `<div class="small ok">✅ Wallet imported & saved. Balances reset.</div>`;
      openModal("Done ✅","<div class='small'>Wallet imported. Balances cleared.</div>");
    } catch(e){
      alert(e.message||"Failed");
    } finally {
      disableAll(false);
      setBusy(false);
    }
  };

  $("btnReceive").onclick = async ()=>{
    try{
      setBusy(true,"Loading…","Fetching address.");
      disableAll(true);
      const st = await api("/api/status");
      if(!st.savedAddr){
        $("panel").innerHTML = `<div class="small bad">No wallet saved.</div>`;
        return;
      }
      $("panel").innerHTML = `
        <h3 style="margin:0 0 8px 0">Receive</h3>
        <div class="small">Address</div>
        <code>${st.savedAddr}</code>
        <div class="small" style="margin-top:8px">Private key is in Settings → Private Key (Admin).</div>
      `;
    } finally {
      disableAll(false);
      setBusy(false);
    }
  };

  $("btnBalance").onclick = async ()=>{
    try{
      setBusy(true,"Loading balance…","Calculating display values.");
      disableAll(true);
      const r = await api("/api/balance");
      if(!r.ok) throw new Error(r.err || "Failed");

      $("panel").innerHTML = `
        <h3 style="margin:0 0 8px 0">Balance (View Only)</h3>
        <div class="small">Address</div>
        <code>${r.addr || "(none)"}</code>

        <div style="margin-top:10px">Total USD: <b>$${r.totalUSD}</b></div>

        <div class="small" style="margin-top:10px">Individual</div>
        <div style="margin-top:8px">ETH: <b>${r.eth}</b> • $${r.usdETH}</div>
        <div>BNB: <b>${r.bnb}</b> • $${r.usdBNB}</div>

        <div class="small" style="margin-top:10px">Editing is in Settings (Admin required).</div>
      `;
    } catch(e){
      alert(e.message||"Failed");
    } finally {
      disableAll(false);
      setBusy(false);
    }
  };

 $("btnTx").onclick = async ()=>{
  try{
    setBusy(true,"Loading…","Fetching transaction history.");
    disableAll(true);

    const r = await api("/api/txs");
    if(!r.ok) throw new Error(r.err||"Failed");

    const pr = await api("/api/prices");
    const pBNB = pr.ok ? parseFloat(pr.bnb||"0") : 0;
    const pETH = pr.ok ? parseFloat(pr.eth||"0") : 0;

    const list = (r.txs || []);
    if(!list.length){
      $("panel").innerHTML = `<div class="small">No transactions yet.</div>`;
      return;
    }

    let html = `<h3>Transaction History</h3>`;

    list.forEach((t,i)=>{
      const coin = t.coin || "BNB";
      const amt  = parseFloat(t.amount || "0");
      const usd  = coin==="ETH" ? amt*pETH : amt*pBNB;

      const st = (t.status||"pending").toLowerCase();
      const stText = st==="success"?"COMPLETED":(st==="failed"?"FAILED":"PENDING");
      const stCls  = st==="success"?"ok":(st==="failed"?"bad":"small");

      html += `
        <div class="card">
          <b>TRANSACTION ${i+1}</b>

          <div class="small">TO ADDRESS</div>
          <code>${t.to}</code>

          <div class="small">AMOUNT IN ${coin}</div>
          <code>${t.amount}</code>

          <div class="small">AMOUNT IN USD</div>
          <code>$${usd.toFixed(2)}</code>

          <div class="small">NONCE</div>
          <code>${t.nonce}</code>

          <div class="small">STATUS</div>
          <b class="${stCls}">${stText}</b>
        </div>
      `;
    });

    $("panel").innerHTML = html;

  } catch(e){
    alert(e.message||"Failed");
  } finally {
    disableAll(false);
    setBusy(false);
  }
};

  $("btnSend").onclick = async ()=>{
    try{
      setBusy(true,"Opening…","Preparing send form.");
      disableAll(true);

      const st = await api("/api/status");
      if(!st.savedAddr){
        $("panel").innerHTML = `<div class="small bad">No wallet saved. Create/import first.</div>`;
        return;
      }

      $("panel").innerHTML = `
        <h3 style="margin:0 0 8px 0">Send (Offline Sign)</h3>
        <div class="small">ESP32 SIGNS only. Phone/PC must broadcast rawTx.</div>

        <div class="small" style="margin-top:10px">Coin</div>
        <select id="coinSel" style="width:100%">
          <option value="BNB">BNB (BSC)</option>
          <option value="ETH">ETH (Ethereum)</option>
        </select>

        <div class="small" style="margin-top:10px">To Address (20 bytes hex)</div>
        <input id="toAddr" placeholder="0x..." style="width:100%">

        <div class="small" style="margin-top:10px">Amount</div>
        <input id="amt" placeholder="0.01" style="width:100%">

        <div class="row" style="margin-top:10px">
          <div style="flex:1;min-width:160px">
            <div class="small">Nonce (from explorer)</div>
            <input id="nonce" placeholder="0" style="width:100%">
          </div>
          <div style="flex:1;min-width:160px">
            <div class="small">Gas Price (gwei)</div>
            <input id="gwei" placeholder="1" style="width:100%">
          </div>
          <div style="flex:1;min-width:160px">
            <div class="small">Gas Limit</div>
            <input id="gl" placeholder="21000" style="width:100%">
          </div>
        </div>

        <div class="row" style="margin-top:10px">
          <div style="flex:1;min-width:160px">
            <div class="small">ChainId (auto)</div>
            <input id="cid" value="56" style="width:100%">
          </div>
        </div>

        <div class="row" style="margin-top:10px">
          <button id="btnSignTx">Sign Tx</button>
        </div>

        <div id="txOut" style="margin-top:10px"></div>
      `;

      function syncChain(){
        const c = $("coinSel").value;
        $("cid").value = (c==="ETH") ? "1" : "56";
      }
      $("coinSel").onchange = syncChain;
      syncChain();

      $("btnSignTx").onclick = async ()=>{
        const coin = ($("coinSel").value||"BNB").trim();
        const to = ($("toAddr").value||"").trim();
        const amt = ($("amt").value||"").trim();
        const nonce = ($("nonce").value||"").trim();
        const gwei = ($("gwei").value||"").trim();
        const gl = ($("gl").value||"").trim();
        const cid = ($("cid").value||"56").trim();

        const ap = prompt("Enter Admin PIN (required to sign)");
        if(!ap) return;

        try{
          setBusy(true,"Signing…","Building & signing transaction offline.");
          disableAll(true);

          const r = await api("/api/signTx",{coin,to,amt,nonce,gwei,gl,cid,ap});
          if(!r.ok) throw new Error(r.err || "Sign failed");

          $("txOut").innerHTML = `
            <div class="small ok">✅ Signed offline</div>
            <div class="small" style="margin-top:8px">Tx Hash:</div>
            <code id="txHashCode">${r.txHash}</code>
            <div class="small" style="margin-top:8px">Raw Tx (broadcast this):</div>
            <textarea readonly>${r.rawTx}</textarea>
            <div class="row" style="margin-top:10px">
              <button class="ghost" id="btnMarkSuccess">Mark Success ✅</button>
              <button class="ghost" id="btnMarkFail">Mark Failed ❌</button>
            </div>
            <div class="small" style="margin-top:8px">
              After broadcasting, use these buttons to store status and update local balance.
            </div>
          `;

          $("btnMarkSuccess").onclick = async ()=>{
            try{
              setBusy(true,"Saving…","Marking success & updating local balance.");
              disableAll(true);
              const rr = await api("/api/markTx",{hash:r.txHash, status:"success"});
              if(!rr.ok) throw new Error(rr.err||"Failed");
              await refreshHome();
              alert("Saved as SUCCESS ✅");
            } catch(e){ alert(e.message||"Failed"); }
            finally{ disableAll(false); setBusy(false); }
          };

          $("btnMarkFail").onclick = async ()=>{
            try{
              setBusy(true,"Saving…","Marking failed.");
              disableAll(true);
              const rr = await api("/api/markTx",{hash:r.txHash, status:"failed"});
              if(!rr.ok) throw new Error(rr.err||"Failed");
              alert("Saved as FAILED ❌");
            } catch(e){ alert(e.message||"Failed"); }
            finally{ disableAll(false); setBusy(false); }
          };

        } catch(e){
          alert(e.message||"Failed");
        } finally {
          disableAll(false);
          setBusy(false);
        }
      };

    } catch(e){
      alert(e.message||"Failed");
    } finally {
      disableAll(false);
      setBusy(false);
    }
  };

  $("btnSettings").onclick = async ()=>{
    try{
      setBusy(true,"Loading…","Opening settings.");
      disableAll(true);

      const st   = await api("/api/status");
      const info = await api("/api/info");
      const wifi = await api("/api/wifi");
      const adm  = await api("/api/adminStatus");
      const bal  = await api("/api/balance");
      const pr   = await api("/api/prices");
      const ph   = await api("/api/priceHistory");

      openModal("Settings", `
        <div class="row" style="justify-content:space-between;align-items:center;margin-bottom:10px">
          <button class="ghost" id="btnSettingsBack">← Back</button>
          <div class="small">Settings</div>
          <div style="width:10px"></div>
        </div>

        <div class="card" style="margin:0">
          <b>Info</b>
          <div class="small">Device: ${info.name}</div>
          <div class="small">Code: ${info.code}</div>
          <div class="small">Version: ${info.ver}</div>
          <div class="small">Saved wallet: ${st.hasSavedWallet ? "<span class='ok'><b>YES</b></span>" : "<span class='bad'><b>NO</b></span>"}</div>
          <div class="small">WiFi SSID: ${wifi.ssid}</div>
        </div>

        <div class="card" style="margin:10px 0 0 0">
          <b>Theme</b>
          <div class="row" style="margin-top:10px">
            <button class="ghost" id="thDefault">Default</button>
            <button class="ghost" id="thPink">Pink</button>
            <button class="ghost" id="thGreen">Green</button>
            <button class="ghost" id="thYellow">Yellow</button>
          </div>
          <div class="small" style="margin-top:8px">Theme saved on your browser.</div>
        </div>

        <div class="card" style="margin:10px 0 0 0">
          <b>Admin</b>
          <div class="small">Admin Password set: ${adm.hasAdmin ? "<span class='ok'><b>YES</b></span>" : "<span class='bad'><b>NO</b></span>"}</div>
          <div class="row" style="margin-top:10px">
            ${adm.hasAdmin ? `<button class="ghost" id="btnAdminChange">Change Admin</button>` : `<button class="ghost" id="btnAdminSetup">Set Admin</button>`}
          </div>
          <div class="small" style="margin-top:8px">Admin must be 4–10 digits.</div>
        </div>

        <div class="card" style="margin:10px 0 0 0">
          <b>Edit Balances (Admin)</b>
          <div class="small">ETH: ${bal.eth}</div>
          <div class="small">BNB: ${bal.bnb}</div>
          <div class="row" style="margin-top:10px">
            <button class="ghost" id="btnEditBal">Edit Balances</button>
          </div>
        </div>

        <div class="card" style="margin:10px 0 0 0">
          <b>Edit Prices (Admin)</b>
          <div class="small">ETH: ${pr.eth}</div>
          <div class="small">BNB: ${pr.bnb}</div>
          <div class="row" style="margin-top:10px">
            <button class="ghost" id="btnEditPri">Edit Prices</button>
          </div>
          <div class="small" style="margin-top:8px">Saving prices also stores snapshot (last 5).</div>
        </div>

        <div class="card" style="margin:10px 0 0 0">
          <b>Price History (last 5)</b>
          <div class="small">uptime seconds, prices, total USD snapshot</div>
          <div style="margin-top:8px" id="phBox"></div>
        </div>

        <div class="card" style="margin:10px 0 0 0">
          <b>Private Key (Admin)</b>
          <div class="small bad">Danger. Use only if you understand.</div>
          <div class="row" style="margin-top:10px">
            <button class="danger" id="btnShowPK">Show Private Key</button>
          </div>
        </div>

        <div class="card" style="margin:10px 0 0 0">
          <b>Security</b>
          <div class="row" style="margin-top:10px">
            <button class="ghost" id="btnChangePin">Change PIN</button>
            <button class="ghost" id="btnChangeWifi">Change WiFi Password</button>
            <button class="danger" id="btnWipeDevice">WIPE Device</button>
          </div>
        </div>
      `);

      $("btnSettingsBack").onclick = closeModal;
      $("thDefault").onclick = ()=>applyTheme("default");
      $("thPink").onclick    = ()=>applyTheme("pink");
      $("thGreen").onclick   = ()=>applyTheme("green");
      $("thYellow").onclick  = ()=>applyTheme("yellow");

      const list = (ph.history||[]);
      let phHtml = "";
      if(!list.length) phHtml = `<div class="small">(empty)</div>`;
      else {
        list.forEach((x,idx)=>{
          phHtml += `<code style="margin:8px 0">#${idx+1} • t=${x.tsec}s • pETH=${x.pETH} • pBNB=${x.pBNB} • total=$${x.total}</code>`;
        });
      }
      $("phBox").innerHTML = phHtml;

      if(!adm.hasAdmin){
        $("btnAdminSetup").onclick = async ()=>{
          const pass = prompt("Set Admin password (4-10 digits)");
          if(!pass) return;
          try{
            setBusy(true,"Saving Admin…","Writing admin verifier.");
            disableAll(true);
            const r = await api("/api/adminSetup",{pass});
            if(!r.ok) throw new Error(r.err||"Failed");
            alert("Admin saved ✅. Re-open Settings.");
          } catch(e){ alert(e.message||"Failed"); }
          finally{ disableAll(false); setBusy(false); }
        };
      } else {
        $("btnAdminChange").onclick = async ()=>{
          const newPass = prompt("New Admin password (4-10 digits)");
          if(!newPass) return;

          const oldPass = prompt("Enter OLD Admin PIN (or leave blank for private-key recovery)");
          let rec = "";
          if(!oldPass){
            rec = prompt("Recovery: Paste PRIVATE KEY exactly (0x...)");
            if(!rec) return;
          }

          try{
            setBusy(true,"Changing Admin…","Updating verifier.");
            disableAll(true);
            const r = await api("/api/adminChange",{oldPass:oldPass||"", newPass, recovery:rec||""});
            if(!r.ok) throw new Error(r.err||"Failed");
            alert("Admin changed ✅. Re-open Settings.");
          } catch(e){ alert(e.message||"Failed"); }
          finally{ disableAll(false); setBusy(false); }
        };
      }

      $("btnEditBal").onclick = async ()=>{
        const ap = prompt("Enter Admin PIN (4-10 digits)");
        if(!ap) return;
        const eth = prompt("ETH amount", bal.eth);
        const bnb = prompt("BNB amount", bal.bnb);
        if(eth==null||bnb==null) return;

        try{
          setBusy(true,"Saving…","Writing balances to flash.");
          disableAll(true);
          const s = await api("/api/setBalances",{eth,bnb,ap});
          if(!s.ok) throw new Error(s.err || "Save failed");
          alert("Balances stored ✅");
          await refreshHome();
        } catch(e){
          alert(e.message||"Failed");
        } finally {
          disableAll(false);
          setBusy(false);
        }
      };

      $("btnEditPri").onclick = async ()=>{
        const ap = prompt("Enter Admin PIN (4-10 digits)");
        if(!ap) return;
        const peth = prompt("ETH price (USD)", pr.eth);
        const pbnb = prompt("BNB price (USD)", pr.bnb);
        if(peth==null||pbnb==null) return;

        try{
          setBusy(true,"Saving…","Writing prices + snapshot.");
          disableAll(true);
          const s = await api("/api/setPrices",{peth,pbnb,ap});
          if(!s.ok) throw new Error(s.err || "Save failed");
          alert("Prices stored ✅ (snapshot saved)");
          await refreshHome();
        } catch(e){
          alert(e.message||"Failed");
        } finally {
          disableAll(false);
          setBusy(false);
        }
      };

      $("btnShowPK").onclick = async ()=>{
        const ap = prompt("Enter Admin PIN (4-10 digits)");
        if(!ap) return;
        const c = prompt("Type CONFIRM to reveal private key");
        if(!c) return;
        try{
          setBusy(true,"Revealing…","Fetching from secure session.");
          disableAll(true);
          const r = await api("/api/private",{confirm:c,ap});
          if(!r.ok) throw new Error(r.err || "Failed");
          openModal("Private Key (danger)", `<code>${r.pk}</code><div class="small bad" style="margin-top:8px">Never share this.</div>`);
        } catch(e){
          alert(e.message||"Failed");
        } finally {
          disableAll(false);
          setBusy(false);
        }
      };

      $("btnChangePin").onclick = async ()=>{
        const newPin = prompt("Enter NEW PIN (4+ digits)");
        if(!newPin) return;
        try{
          setBusy(true,"Changing PIN…","Re-encrypting wallet with new PIN.");
          disableAll(true);
          const r = await api("/api/changePin",{newPin});
          if(!r.ok) throw new Error(r.err || "Failed");
          alert("PIN changed ✅ (Lock & unlock again recommended)");
        } catch(e){
          alert(e.message||"Failed");
        } finally {
          disableAll(false);
          setBusy(false);
        }
      };

      $("btnChangeWifi").onclick = async ()=>{
        const newPass = prompt("New WiFi password (8-63 chars)");
        if(!newPass) return;
        try{
          setBusy(true,"Updating WiFi…","Saving password, reboot required.");
          disableAll(true);
          const r = await api("/api/setWifiPass",{pass:newPass});
          if(!r.ok) throw new Error(r.err || "Failed");
          alert("WiFi password updated. Device will reboot.");
          setTimeout(()=>location.reload(), 800);
        } catch(e){
          alert(e.message||"Failed");
        } finally {
          disableAll(false);
          setBusy(false);
        }
      };

      $("btnWipeDevice").onclick = async ()=>{
        const w = prompt("Type WIPE to erase EVERYTHING");
        if((w||"").trim().toUpperCase() !== "WIPE") return;
        const pin = prompt("Enter PIN to confirm wipe");
        if(!pin) return;

        try{
          setBusy(true,"WIPING…","Erasing flash storage now.");
          disableAll(true);
          const r = await api("/api/wipe",{wipe:w,pin});
          if(!r.ok) throw new Error(r.err || "Wipe failed");
          alert("Wiped ✅ device rebooting");
          setTimeout(()=>location.reload(), 800);
        } catch(e){
          alert(e.message||"Failed");
        } finally {
          disableAll(false);
          setBusy(false);
        }
      };

    } catch(e){
      alert(e.message||"Failed");
    } finally {
      disableAll(false);
      setBusy(false);
    }
  };
}

boot();
</script>
</body></html>
)HTML";

// ================= ROUTES / API =================
static inline void routeUI() {
  server.sendHeader("Cache-Control", "no-store");
  server.send(200, "text/html", FPSTR(PAGE));
}

static inline void apiStatus() {
  bool pinSet = smHasPin();
  bool hasSaved = smHasSavedWallet();
  String savedAddr = smGetSavedAddress();
  int fails = smGetFails();

  String shortA = (savedAddr.length() > 12)
    ? (savedAddr.substring(0,6) + "..." + savedAddr.substring(savedAddr.length()-4))
    : savedAddr;

  int triesLeft = MAX_FAILS - fails;
  if (triesLeft < 0) triesLeft = 0;

  String out = "{";
  out += "\"pinSet\":" + String(pinSet ? "true" : "false") + ",";
  out += "\"hasSavedWallet\":" + String(hasSaved ? "true" : "false") + ",";
  out += "\"savedAddr\":\"" + jsonEscape(savedAddr) + "\",";
  out += "\"short\":\"" + jsonEscape(shortA) + "\",";
  out += "\"triesLeft\":" + String(triesLeft);
  out += "}";
  sendJSON(out);
}

static inline void apiInfo() {
  sendJSON(String("{\"ok\":true,\"name\":\"") + DEVICE_NAME +
           "\",\"code\":\"" + DEVICE_CODE +
           "\",\"ver\":\"" + VERSION_STR + "\"}");
}

static inline void apiWifi() {
  String ssid, pass;
  wifiLoad(ssid, pass);
  sendJSON(String("{\"ok\":true,\"ssid\":\"") + jsonEscape(ssid) + "\"}");
}

static inline void apiPrices() {
  if (!authed()) return sendJSON("{\"ok\":false,\"err\":\"Not authed\"}", 403);
  sendJSON(String("{\"ok\":true,\"eth\":\"") + jsonEscape(priceETH) +
           "\",\"bnb\":\"" + jsonEscape(priceBNB) + "\"}");
}

static inline void apiPriceHistory() {
  if (!authed()) return sendJSON("{\"ok\":false,\"err\":\"Not authed\"}", 403);
  sendJSON(String("{\"ok\":true,\"history\":") + smGetPriceHistoryJson() + "}");
}

static inline void apiAdminStatus() {
  if (!authed()) return sendJSON("{\"ok\":false,\"err\":\"Not authed\"}", 403);
  bool h = smHasAdmin();
  sendJSON(String("{\"ok\":true,\"hasAdmin\":") + (h ? "true" : "false") + "}");
}

static inline void apiAdminSetup() {
  if (!authed()) return sendJSON("{\"ok\":false,\"err\":\"Not authed\"}", 403);
  if (smHasAdmin()) return sendJSON("{\"ok\":false,\"err\":\"Admin already set\"}", 400);

  String pass = server.arg("pass");
  pass.trim();
  if (!isDigitsLen(pass, 4, 10)) return sendJSON("{\"ok\":false,\"err\":\"Admin must be 4-10 digits\"}", 400);

  bool ok = smAdminSetup(pass);
  sendJSON(ok ? "{\"ok\":true}" : "{\"ok\":false,\"err\":\"Admin setup failed\"}", ok ? 200 : 500);
}

static inline void apiAdminChange() {
  if (!authed()) return sendJSON("{\"ok\":false,\"err\":\"Not authed\"}", 403);
  if (!smHasAdmin()) return sendJSON("{\"ok\":false,\"err\":\"Admin not set\"}", 400);

  String oldPass = server.arg("oldPass"); oldPass.trim();
  String newPass = server.arg("newPass"); newPass.trim();
  String recovery= server.arg("recovery"); recovery.trim();

  if (!isDigitsLen(newPass,4,10)) return sendJSON("{\"ok\":false,\"err\":\"New admin must be 4-10 digits\"}", 400);

  if (!smAdminChange(oldPass, newPass, recovery)) {
    return sendJSON("{\"ok\":false,\"err\":\"Admin change failed (need old admin OR correct private key)\"}", 401);
  }
  sendJSON("{\"ok\":true}");
}

static inline void apiSetup() {
  String p = server.arg("pin");
  if (p.length() < 4) return sendJSON("{\"ok\":false,\"err\":\"PIN too short\"}", 400);
  if (smHasPin()) return sendJSON("{\"ok\":false,\"err\":\"PIN already set\"}", 400);

  bool ok = smFirstTimeSetup(p);
  sendJSON(ok ? "{\"ok\":true}" : "{\"ok\":false,\"err\":\"Setup failed\"}", ok ? 200 : 500);
}

static inline void apiLogin() {
  String p = server.arg("pin");
  if (!smHasPin()) return sendJSON("{\"ok\":false,\"err\":\"PIN not set\"}", 400);

  String addr, pk;
  if (!smUnlock(p, addr, pk)) {
    int f = smGetFails();
    f++;
    smSetFails(f);

    if (f >= MAX_FAILS) {
      sendJSON("{\"ok\":false,\"wiped\":true,\"err\":\"Too many wrong attempts. WIPING.\"}", 403);
      delay(250);
      wipeRAMSecrets();
      smStrongWipeAllNVS();
      delay(250);
      ESP.restart();
      return;
    }

    int triesLeft = MAX_FAILS - f;
    if (triesLeft < 0) triesLeft = 0;
    sendJSON(String("{\"ok\":false,\"err\":\"Wrong PIN\",\"triesLeft\":") + triesLeft + "}", 401);
    return;
  }

  smResetFails();
  smLoadSettings();

  sessionAuthed = true;
  sessionToken = randomToken();
  sessionPin = p;

  walletAddress = addr;
  privateKey = pk;

  sendJSON("{\"ok\":true,\"t\":\"" + sessionToken + "\"}");
}

static inline void apiLogout() {
  wipeRAMSecrets();
  sendJSON("{\"ok\":true}");
}

static inline bool requireOverwriteConfirmIfWalletExists() {
  if (!smHasSavedWallet()) return true;

  String yes = server.arg("yes"); yes.trim(); yes.toUpperCase();
  String pin = server.arg("pin"); pin.trim();
  String ap  = server.arg("ap");  ap.trim();

  if (yes != "YES") return false;
  if (!smVerifyPinOnly(pin)) return false;
  if (!smHasAdmin()) return false;
  if (!smAdminVerify(ap)) return false;

  return true;
}

static inline void apiCreate() {
  if (!authed()) return sendJSON("{\"ok\":false,\"err\":\"Not authed\"}", 403);

  if (!requireOverwriteConfirmIfWalletExists()) {
    return sendJSON("{\"ok\":false,\"err\":\"Wallet exists. Need YES + PIN + Admin\"}", 401);
  }

  String pk, addr;
  performAccountGeneration(pk, addr);

  if (!smSaveWallet(addr, pk, sessionPin)) return sendJSON("{\"ok\":false,\"err\":\"Save failed\"}", 500);

  walletAddress = addr;
  privateKey = pk;

  resetBalancesOnNewWallet();
  sendJSON("{\"ok\":true}");
}

static inline void apiImport() {
  if (!authed()) return sendJSON("{\"ok\":false,\"err\":\"Not authed\"}", 403);

  if (!requireOverwriteConfirmIfWalletExists()) {
    return sendJSON("{\"ok\":false,\"err\":\"Wallet exists. Need YES + PIN + Admin\"}", 401);
  }

  String addr = server.arg("addr");
  String pk   = server.arg("pk");
  if (addr.length() < 8 || pk.length() < 8) return sendJSON("{\"ok\":false,\"err\":\"Bad input\"}", 400);

  if (!smSaveWallet(addr, pk, sessionPin)) return sendJSON("{\"ok\":false,\"err\":\"Save failed\"}", 500);

  walletAddress = addr;
  privateKey = pk;

  resetBalancesOnNewWallet();
  sendJSON("{\"ok\":true}");
}

static inline void apiPrivate() {
  if (!authed()) return sendJSON("{\"ok\":false,\"err\":\"Not authed\"}", 403);
  if (!hasWalletRAM()) return sendJSON("{\"ok\":false,\"err\":\"Unlock first\"}", 400);

  if (!smHasAdmin()) return sendJSON("{\"ok\":false,\"err\":\"Admin not set\"}", 403);

  String ap = server.arg("ap");
  ap.trim();
  if (!smAdminVerify(ap)) return sendJSON("{\"ok\":false,\"err\":\"Admin password wrong\"}", 401);

  String c = server.arg("confirm");
  c.trim(); c.toUpperCase();
  if (c != "CONFIRM") return sendJSON("{\"ok\":false,\"err\":\"Type CONFIRM\"}", 400);

  sendJSON("{\"ok\":true,\"pk\":\"" + jsonEscape(privateKey) + "\"}");
}

static inline void apiSummary() {
  if (!authed()) return sendJSON("{\"ok\":false,\"err\":\"Not authed\"}", 403);

  float total = calcTotalUSD();
  char bt[24];
  format2(total, bt, sizeof(bt));

  String lastS = getLastTotalStr();
  float last = lastS.toFloat();
  String pctStr = "";
  if (last > 0.000001f) {
    float pct = ((total - last) / last) * 100.0f;
    char pbuf[24];
    dtostrf(pct, 0, 2, pbuf);
    pctStr = String(pbuf);
  }

  sendJSON(String("{\"ok\":true,\"totalUSD\":\"") + String(bt) + "\",\"pct\":\"" + jsonEscape(pctStr) + "\"}");
}

static inline void apiBalance() {
  if (!authed()) return sendJSON("{\"ok\":false,\"err\":\"Not authed\"}", 403);

  String eth  = weiToCoin(ethWei);
  String bnb  = weiToCoin(bnbWei);

  float e = eth.toFloat() * priceETH.toFloat();
  float b = bnb.toFloat() * priceBNB.toFloat();
  float total = e + b;

  char be[20], bb[20], bt[24];
  format2(e, be, sizeof(be));
  format2(b, bb, sizeof(bb));
  format2(total, bt, sizeof(bt));

  String out = "{";
  out += "\"ok\":true,";
  out += "\"addr\":\"" + jsonEscape(smGetSavedAddress()) + "\",";
  out += "\"eth\":\"" + jsonEscape(eth) + "\",\"bnb\":\"" + jsonEscape(bnb) + "\",";
  out += "\"usdETH\":\"" + String(be) + "\",\"usdBNB\":\"" + String(bb) + "\",";
  out += "\"totalUSD\":\"" + String(bt) + "\"";
  out += "}";
  sendJSON(out);
}

static inline void apiSetBalances() {
  if (!authed()) return sendJSON("{\"ok\":false,\"err\":\"Not authed\"}", 403);
  if (!smHasAdmin()) return sendJSON("{\"ok\":false,\"err\":\"Admin not set\"}", 403);

  String ap = server.arg("ap"); ap.trim();
  if (!smAdminVerify(ap)) return sendJSON("{\"ok\":false,\"err\":\"Admin password wrong\"}", 401);

  ethWei  = coinToWei(server.arg("eth"));
  bnbWei  = coinToWei(server.arg("bnb"));

  smSaveSettings();
  sendJSON("{\"ok\":true}");
}

static inline void apiSetPrices() {
  if (!authed()) return sendJSON("{\"ok\":false,\"err\":\"Not authed\"}", 403);
  if (!smHasAdmin()) return sendJSON("{\"ok\":false,\"err\":\"Admin not set\"}", 403);

  String ap = server.arg("ap"); ap.trim();
  if (!smAdminVerify(ap)) return sendJSON("{\"ok\":false,\"err\":\"Admin password wrong\"}", 401);

  priceETH  = server.arg("peth");
  priceBNB  = server.arg("pbnb");
  priceETH.trim(); priceBNB.trim();

  smSaveSettings();

  float total = calcTotalUSD();
  smPushPriceSnap(total);

  char bt[24];
  format2(total, bt, sizeof(bt));
  setLastTotalStr(String(bt));

  sendJSON("{\"ok\":true}");
}

static inline void apiSetWifiPass() {
  if (!authed()) return sendJSON("{\"ok\":false,\"err\":\"Not authed\"}", 403);

  String pass = server.arg("pass");
  pass.trim();
  if (pass.length() < 8 || pass.length() > 63) {
    return sendJSON("{\"ok\":false,\"err\":\"Password must be 8-63 chars\"}", 400);
  }

  String ssid, curPass;
  wifiLoad(ssid, curPass);
  wifiSave(ssid, pass);

  sendJSON("{\"ok\":true,\"reboot\":true}");
  delay(250);
  ESP.restart();
}

static inline void apiChangePin() {
  if (!authed()) return sendJSON("{\"ok\":false,\"err\":\"Not authed\"}", 403);

  String newPin = server.arg("newPin");
  newPin.trim();
  if (newPin.length() < 4) return sendJSON("{\"ok\":false,\"err\":\"PIN too short\"}", 400);

  if (!smChangePin(sessionPin, newPin)) return sendJSON("{\"ok\":false,\"err\":\"Change PIN failed\"}", 500);

  sessionPin = newPin;
  sendJSON("{\"ok\":true}");
}

static inline void apiWipe() {
  if (!authed()) return sendJSON("{\"ok\":false,\"err\":\"Not authed\"}", 403);

  String w = server.arg("wipe");
  w.trim(); w.toUpperCase();
  String p = server.arg("pin");

  if (w != "WIPE") return sendJSON("{\"ok\":false,\"err\":\"Type WIPE\"}", 400);
  if (!smVerifyPinOnly(p)) return sendJSON("{\"ok\":false,\"err\":\"Wrong PIN\"}", 401);

  sendJSON("{\"ok\":true}");
  delay(200);

  wipeRAMSecrets();
  smStrongWipeAllNVS();

  delay(200);
  ESP.restart();
}

// =================== SIGN TX + SAVE RECORD ===================
static inline void apiSignTx() {
  if (!authed()) return sendJSON("{\"ok\":false,\"err\":\"Not authed\"}", 403);
  if (!hasWalletRAM()) return sendJSON("{\"ok\":false,\"err\":\"Unlock first\"}", 400);
  if (!smHasAdmin()) return sendJSON("{\"ok\":false,\"err\":\"Admin not set\"}", 403);

  String ap = server.arg("ap"); ap.trim();
  if (!smAdminVerify(ap)) return sendJSON("{\"ok\":false,\"err\":\"Admin wrong\"}", 401);

  String coin = server.arg("coin"); coin.trim();
  if (coin != "BNB" && coin != "ETH") coin = "BNB";

  String to = server.arg("to"); to.trim();
  String amt = server.arg("amt"); amt.trim();
  String nonceS = server.arg("nonce"); nonceS.trim();
  String gweiS  = server.arg("gwei"); gweiS.trim();
  String glS    = server.arg("gl"); glS.trim();
  String cidS   = server.arg("cid"); cidS.trim();

  if (!to.startsWith("0x") && !to.startsWith("0X")) return sendJSON("{\"ok\":false,\"err\":\"TO must start 0x\"}", 400);
  if (to.length() != 42) return sendJSON("{\"ok\":false,\"err\":\"TO must be 20 bytes hex\"}", 400);

  uint64_t nonce = (uint64_t)nonceS.toInt();
  uint64_t gwei  = (uint64_t)gweiS.toInt();
  uint64_t gl    = (uint64_t)glS.toInt();
  uint32_t cid   = (uint32_t)cidS.toInt();

  if (coin == "ETH") cid = 1;
  if (coin == "BNB") cid = 56;
  if (gl == 0) gl = 21000;

  String valueWei = coinToWei(amt);
  if (valueWei.length()==0) valueWei = "0";

  String* balWeiPtr = (coin=="ETH") ? &ethWei : &bnbWei;
  if (cmpDecStr(*balWeiPtr, valueWei) < 0) {
    return sendJSON("{\"ok\":false,\"err\":\"Local balance is smaller than amount (edit balances in Settings).\"}", 400);
  }

  String rawTx, txHash, err;
  bool ok = buildSignedTxEIP155(to, valueWei, nonce, gwei, gl, cid, privateKey, rawTx, txHash, err);
  if (!ok) return sendJSON(String("{\"ok\":false,\"err\":\"") + jsonEscape(err) + "\"}", 400);

  TxRecord tr;
  tr.coin = coin;
  tr.to = to;
  tr.amountCoin = amt;
  tr.nonce = nonce;
  tr.gasGwei = gwei;
  tr.gasLimit = gl;
  tr.chainId = cid;
  tr.txHash = txHash;
  tr.rawTx = rawTx;
  tr.status = "pending";
  tr.tsec = upSeconds();
  smPushTx(tr);

  sendJSON(String("{\"ok\":true,\"rawTx\":\"") + jsonEscape(rawTx) + "\",\"txHash\":\"" + jsonEscape(txHash) + "\"}");
}

static inline void apiTxs() {
  if (!authed()) return sendJSON("{\"ok\":false,\"err\":\"Not authed\"}", 403);
  sendJSON(String("{\"ok\":true,\"txs\":") + smGetTxArrayJson() + "}");
}

static inline void apiMarkTx() {
  if (!authed()) return sendJSON("{\"ok\":false,\"err\":\"Not authed\"}", 403);
  String hash = server.arg("hash"); hash.trim();
  String status = server.arg("status"); status.trim();
  if (!hash.startsWith("0x") || hash.length() < 10) return sendJSON("{\"ok\":false,\"err\":\"Bad hash\"}", 400);
  if (status != "success" && status != "failed") return sendJSON("{\"ok\":false,\"err\":\"Bad status\"}", 400);

  // read tx first (so we can deduct on success reliably)
  TxRecord tr;
  int slot = -1;
  if (!txFindByHash(hash, tr, slot)) {
    return sendJSON("{\"ok\":false,\"err\":\"Tx not found in last 3\"}", 404);
  }

  bool ok = smSetTxStatusByHash(hash, status);
  if (!ok) return sendJSON("{\"ok\":false,\"err\":\"Tx not found in last 3\"}", 404);

  if (status == "success") {
    String wei = coinToWei(tr.amountCoin);
    if (tr.coin == "ETH") {
      if (cmpDecStr(ethWei, wei) >= 0) ethWei = subDecStr(ethWei, wei);
    } else {
      if (cmpDecStr(bnbWei, wei) >= 0) bnbWei = subDecStr(bnbWei, wei);
    }
    smSaveSettings();
  }

  sendJSON("{\"ok\":true}");
}

// ================= SETUP & LOOP =================
void setup() {
  Serial.begin(115200);
  smLoadSettings();

#if ENABLE_WEB_UI
  String ssid, pass;
  wifiLoad(ssid, pass);

  btStop();
  WiFi.mode(WIFI_AP);
  WiFi.setSleep(false);
  WiFi.softAP(ssid.c_str(), pass.c_str());
  delay(200);

  Serial.println("\n=== Singularity Money Web Prototype ===");
  Serial.print("SSID: "); Serial.println(ssid);
  Serial.print("PASS: "); Serial.println(pass);
  Serial.print("Open: http://"); Serial.println(WiFi.softAPIP());

  server.on("/", HTTP_GET, routeUI);

  server.on("/api/status",        HTTP_GET,  apiStatus);
  server.on("/api/info",          HTTP_GET,  apiInfo);
  server.on("/api/wifi",          HTTP_GET,  apiWifi);
  server.on("/api/prices",        HTTP_GET,  apiPrices);
  server.on("/api/priceHistory",  HTTP_GET,  apiPriceHistory);
  server.on("/api/summary",       HTTP_GET,  apiSummary);

  server.on("/api/adminStatus",   HTTP_GET,  apiAdminStatus);
  server.on("/api/adminSetup",    HTTP_POST, apiAdminSetup);
  server.on("/api/adminChange",   HTTP_POST, apiAdminChange);

  server.on("/api/setup",         HTTP_POST, apiSetup);
  server.on("/api/login",         HTTP_POST, apiLogin);
  server.on("/api/logout",        HTTP_ANY,  apiLogout);

  server.on("/api/create",        HTTP_ANY,  apiCreate);
  server.on("/api/import",        HTTP_POST, apiImport);

  server.on("/api/private",       HTTP_ANY,  apiPrivate);

  server.on("/api/balance",       HTTP_GET,  apiBalance);
  server.on("/api/setBalances",   HTTP_POST, apiSetBalances);
  server.on("/api/setPrices",     HTTP_POST, apiSetPrices);

  server.on("/api/signTx",        HTTP_POST, apiSignTx);
  server.on("/api/txs",           HTTP_GET,  apiTxs);
  server.on("/api/markTx",        HTTP_POST, apiMarkTx);

  server.on("/api/setWifiPass",   HTTP_POST, apiSetWifiPass);
  server.on("/api/changePin",     HTTP_POST, apiChangePin);

  server.on("/api/wipe",          HTTP_ANY,  apiWipe);

  server.onNotFound([](){ sendJSON("{\"ok\":false,\"err\":\"404\"}", 404); });

  server.begin();
#else
  WiFi.mode(WIFI_OFF);
  btStop();
#endif
}

void loop() {
#if ENABLE_WEB_UI
  server.handleClient();
  delay(1);
#else
  delay(1000);
#endif
}
