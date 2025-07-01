# CppPKCS11Kit
CppPKCS11Kit is a robust, modular, and thread-safe C++14 application designed to interact with PKCS#11 tokens. It utilizes SoftHSMv2, a software-based HSM, to simulate secure hardware-backed cryptographic operations.

---

## How It Works

#### 1. **Configuration Layer**

* Uses `config/app_config.h.in` and CMake to generate `app_config.h`
* Injects `PKCS11_LIB_PATH` and `USER_PIN` at build time

#### 2. **PKCS#11 Wrapper Layer**

* **`PKCS11Library` (Singleton)**: Loads and initializes the shared lib (e.g., `libsofthsm2.so`)
* **`PKCS11Session`**: RAII wrapper for login/logout, open/close session
* Translates all errors via `PKCS11Exception`

#### 3. **Crypto Manager Layer**

* High-level API
* Thread-local session with `thread_local std::unique_ptr`
* Exposes methods like `generate_rsa_key_pair_on_token`, `sign_data_on_token`, etc.

#### 4. **Utility Layer**

* Hex encoding/decoding helpers
* Secure memory erasure

#### 5. **Main Application**

* Demonstrates:

  * RSA key pair generation, sign/verify, encrypt/decrypt
  * AES key gen/encryption/decryption
  * SHA-256 hashing
  * Thread-safe concurrent operations

---

## Cryptographic Operations

### RSA Key Generation

```cpp
// Generates 2048-bit RSA key pair
// Returns CK_OBJECT_HANDLEs for public and private keys
```

### RSA Sign / Verify

```cpp
sign_data_on_token(data, hPrivateKey);
verify_signature_on_token(data, signature, hPublicKey);
```

### RSA Encrypt / Decrypt

```cpp
auto ciphertext = encrypt_rsa_data_on_token(plaintext, hPublicKey);
auto plaintext = decrypt_rsa_data_on_token(ciphertext, hPrivateKey);
```

### AES CBC Encrypt / Decrypt

```cpp
auto ciphertext = encrypt_aes_data_on_token(plaintext, hAesKey, iv);
auto decrypted = decrypt_aes_data_on_token(ciphertext, hAesKey, iv);
```

### SHA-256 Hashing

```cpp
std::vector<CK_BYTE> hash = sha256_digest_on_token(data);
```

---

## Getting Started on Ubuntu

### 1. 📋 Install Prerequisites

```bash
sudo apt update
sudo apt install build-essential cmake softhsm2 libsofthsm2-dev
```

### 2. 🔐 Configure SoftHSMv2

```bash
mkdir -p ~/.config/softhsm2/tokens
cp /etc/softhsm2.conf ~/.config/softhsm2/softhsm2.conf
chown $USER:$USER ~/.config/softhsm2/softhsm2.conf
chmod 644 ~/.config/softhsm2/softhsm2.conf
```

Edit `~/.config/softhsm2/softhsm2.conf`:

```
directories.tokendir = /home/YOUR_USER/.config/softhsm2/tokens
```

Export config path:

```bash
echo 'export SOFTHSM2_CONF=$HOME/.config/softhsm2/softhsm2.conf' >> ~/.bashrc
source ~/.bashrc
```

### 3. 🧱 Initialize a Token

```bash
softhsm2-util --init-token --slot 0 --label "MyTestToken" --pin 1234 --so-pin 123456
```

### 4. 📦 Project Structure

```
CppPKCS11Kit/
├── src/
│   ├── main.cpp
│   ├── core/
│   │   ├── pkcs11_wrapper.cpp
│   │   └── crypto_manager.cpp
│   └── utils/
│       └── hex_utils.cpp
├── include/
│   ├── core/
│   │   ├── pkcs11_wrapper.hpp
│   │   └── crypto_manager.hpp
│   └── utils/
│       └── hex_utils.hpp
├── config/
│   └── app_config.h.in
├── test/
│   └── crypto_tests.cpp
├── CMakeLists.txt
└── README.md
```

### 5. 🧱 Build

```bash
mkdir build && cd build
cmake .. \
  -DPKCS11_LIBRARY_PATH_VAR="/usr/lib/softhsm/libsofthsm2.so" \
  -DUSER_PIN_VAR="1234" \
  -DBUILD_TESTS=ON
cmake --build .
```

### 6. ▶️ Run

```bash
./bin/CppPKCS11Kit
```

### 7. ✅ Run Tests

```bash
ctest --verbose
# or
./bin/crypto_tests
```

---

## 🧪 Sample Test Output

```
[==========] Running 7 tests from 1 test suite.
[----------] Global test environment set-up.
[ RUN      ] CryptoTestFixture.RSAEncryptAndDecrypt
[       OK ] CryptoTestFixture.RSAEncryptAndDecrypt (X ms)
...
[==========] 7 tests from 1 test suite ran. (XX ms total)
[  PASSED  ] 7 tests.
```

---

## ⚠️ Security Notes

* **PIN Handling**: NEVER hardcode PINs in production. Use secure vaults or input prompts.
* **Memory Management**: For highly sensitive data, consider mlock/VirtualLock for secure memory.
* **Session Scaling**: Production use may require session pooling, reconnection, and state recovery logic.
* **Key Naming**: Replace string-based IDs with hash-based or UUIDs for better security.

---

## 🐛 Troubleshooting

| Issue                             | Fix                                                 |
| --------------------------------- | --------------------------------------------------- |
| `PKCS11_LIBRARY_PATH_VAR` not set | Ensure correct CMake arguments                      |
| `CKR_PIN_INCORRECT`               | Check if correct PIN was passed via `USER_PIN_VAR`  |
| No slots with tokens              | Did you run `softhsm2-util --init-token`?           |
| `CKR_DEVICE_ERROR`                | Token might be full or need re-login                |
| Segfault                          | Check library path, permissions, corrupted .so file |

Check environment:

```bash
echo $SOFTHSM2_CONF
cat ~/.config/softhsm2/softhsm2.conf
```

---
