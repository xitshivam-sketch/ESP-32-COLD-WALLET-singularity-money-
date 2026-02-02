🔐 Singularity Money — ESP32 Cold Wallet (Prototype-1)

Singularity Money Prototype-1 is a fully working ESP32-based cold crypto wallet designed to generate, store, and sign real blockchain transactions completely offline.

This project proves that an ESP32 can act as a true cold signer, handling real cryptography and transaction signing for Ethereum and BNB Smart Chain, without relying on internet connectivity, RPC nodes, or third-party services.

Prototype-1 is feature-complete and frozen.
No further updates or bug fixes are planned.

✨ Key Features
🔑 Real Cryptography

secp256k1 private key generation

Keccak-256 address derivation

Fully compatible with MetaMask / Trust Wallet

Tested with real funds on BSC

🔐 Secure Key Storage

Private key encrypted using:

PBKDF2-HMAC-SHA256

AES-256-GCM

PIN-derived encryption key

Decrypted key exists only in RAM

🛡️ Security Model

User PIN (first-boot mandatory)

Separate Admin PIN for sensitive actions

3 wrong PIN attempts → automatic full wipe

Overwrite protection for wallet creation/import

Manual secure wipe option

✍️ Offline Transaction Signing

Legacy EIP-155 transaction signing

Supports ETH (chainId 1) and BNB (chainId 56)

Manual control over:

Nonce

Gas price

Gas limit

Outputs:

Raw signed transaction hex

Transaction hash

Transactions can be broadcast later using any external tool

📜 Transaction History

Stores last 3 transactions in encrypted NVS

Each transaction includes:

Amount, recipient, nonce

Gas details, chainId

RawTx, txHash, status

Mark transactions as success / failed

Local balance updated accordingly

🌐 Web-UI (Local Only)

ESP32 runs as a Wi-Fi Access Point

Browser-based UI at http://192.168.4.1

No internet access required

Features:

Wallet management

Balance & USD conversion

Price snapshots

Transaction history

Settings & security controls

Multiple UI themes

📊 Balance & Price Tracking

Local balance ledger (offline-safe)

Wei ↔ ETH / BNB conversion

Manual USD price entry

Price snapshot history with % change

🚫 What This Project Does NOT Do

No blockchain RPC calls

No automatic balance fetching

No transaction broadcasting

No cloud services

No backend servers

No secure element (software-only security)

This design is intentional to keep the wallet fully offline and auditable.

🧪 Project Status

✅ Cryptographically correct

✅ Tested with real transactions

✅ Stable and compiling

🔒 Prototype-1 is frozen

🚧 Future work will be done in Prototype-2 (hardware UI)

👤 Author

Shivam Kumar
