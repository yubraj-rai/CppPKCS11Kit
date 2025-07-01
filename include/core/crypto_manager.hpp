#ifndef CRYPTO_MANAGER_HPP
#define CRYPTO_MANAGER_HPP

#include "pkcs11_wrapper.hpp"
#include <string>
#include <vector>
#include <mutex> // For thread-local session management
#include <random> // For IV generation

namespace crypto {

// --- High-level Crypto Application Logic ---
class CryptoManager {
public:
    // @brief Constructor. Initializes the CryptoManager with the PKCS#11 library path.
    // @param pkcs11_library_path The path to the PKCS#11 shared library.
    // @param user_pin The user PIN for the PKCS#11 token.
    explicit CryptoManager(const std::string& pkcs11_library_path, const std::string& user_pin);

    // @brief Destructor. Ensures PKCS#11 library finalization.
    ~CryptoManager();

    // @brief Get the ID of the first available PKCS#11 slot.
    // @return The ID of the first slot.
    // @throws pkcs11::PKCS11Exception if no slots are found.
    CK_SLOT_ID get_first_slot_id();

    // @brief Generate an RSA key pair on the PKCS#11 token.
    // @param slot_id The ID of the slot to use.
    // @param public_key_id A unique ID for the public key.
    // @param private_key_id A unique ID for the private key.
    // @param modulus_bits The desired RSA modulus size in bits (e.g., 2048).
    // @return A pair of CK_OBJECT_HANDLEs: {public_key_handle, private_key_handle}.
    // @throws pkcs11::PKCS11Exception if any PKCS#11 operation fails.
    std::pair<CK_OBJECT_HANDLE, CK_OBJECT_HANDLE> generate_rsa_key_pair_on_token(
        CK_SLOT_ID slot_id,
        const std::vector<CK_BYTE>& public_key_id,
        const std::vector<CK_BYTE>& private_key_id,
        CK_ULONG modulus_bits);

    // @brief Generate an AES symmetric key on the PKCS#11 token.
    // @param slot_id The ID of the slot to use.
    // @param key_id A unique ID for the AES key.
    // @param key_bits The desired AES key size in bits (e.g., 128, 256).
    // @return The CK_OBJECT_HANDLE of the generated AES key.
    // @throws pkcs11::PKCS11Exception if any PKCS#11 operation fails.
    CK_OBJECT_HANDLE generate_aes_key_on_token(
        CK_SLOT_ID slot_id,
        const std::vector<CK_BYTE>& key_id,
        CK_ULONG key_bits);

    // @brief Sign data using a private RSA key on the PKCS#11 token.
    // @param slot_id The ID of the slot to use.
    // @param private_key_handle The handle of the private key on the token.
    // @param data The data to be signed.
    // @return The signature bytes.
    // @throws pkcs11::PKCS11Exception if any PKCS#11 operation fails.
    std::vector<CK_BYTE> sign_data_on_token(
        CK_SLOT_ID slot_id,
        CK_OBJECT_HANDLE private_key_handle,
        const std::vector<CK_BYTE>& data);

    // @brief Verify a signature using a public RSA key on the PKCS#11 token.
    // @param slot_id The ID of the slot to use.
    // @param public_key_handle The handle of the public key on the token.
    // @param data The original data.
    // @param signature The signature to verify.
    // @return True if the signature is valid, false otherwise.
    // @throws pkcs11::PKCS11Exception if any PKCS#11 operation fails (other than CKR_SIGNATURE_INVALID).
    bool verify_signature_on_token(
        CK_SLOT_ID slot_id,
        CK_OBJECT_HANDLE public_key_handle,
        const std::vector<CK_BYTE>& data,
        const std::vector<CK_BYTE>& signature);

    // @brief Encrypt data using a public RSA key on the PKCS#11 token.
    // @param slot_id The ID of the slot to use.
    // @param public_key_handle The handle of the public key on the token.
    // @param plaintext The data to be encrypted.
    // @return The ciphertext bytes.
    // @throws pkcs11::PKCS11Exception if any PKCS#11 operation fails.
    std::vector<CK_BYTE> encrypt_rsa_data_on_token(
        CK_SLOT_ID slot_id,
        CK_OBJECT_HANDLE public_key_handle,
        const std::vector<CK_BYTE>& plaintext);

    // @brief Decrypt data using a private RSA key on the PKCS#11 token.
    // @param slot_id The ID of the slot to use.
    // @param private_key_handle The handle of the private key on the token.
    // @param ciphertext The data to be decrypted.
    // @return The decrypted plaintext bytes.
    // @throws pkcs11::PKCS11Exception if any PKCS#11 operation fails.
    std::vector<CK_BYTE> decrypt_rsa_data_on_token(
        CK_SLOT_ID slot_id,
        CK_OBJECT_HANDLE private_key_handle,
        const std::vector<CK_BYTE>& ciphertext);

    // @brief Encrypt data using a symmetric AES key on the PKCS#11 token (CBC mode).
    // @param slot_id The ID of the slot to use.
    // @param aes_key_handle The handle of the AES key on the token.
    // @param plaintext The data to be encrypted.
    // @param iv The initialization vector (16 bytes for AES CBC).
    // @return The ciphertext bytes.
    // @throws pkcs11::PKCS11Exception if any PKCS#11 operation fails.
    std::vector<CK_BYTE> encrypt_aes_data_on_token(
        CK_SLOT_ID slot_id,
        CK_OBJECT_HANDLE aes_key_handle,
        const std::vector<CK_BYTE>& plaintext,
        const std::vector<CK_BYTE>& iv);

    // @brief Decrypt data using a symmetric AES key on the PKCS#11 token (CBC mode).
    // @param slot_id The ID of the slot to use.
    // @param aes_key_handle The handle of the AES key on the token.
    // @param ciphertext The data to be decrypted.
    // @param iv The initialization vector (16 bytes for AES CBC).
    // @return The decrypted plaintext bytes.
    // @throws pkcs11::PKCS11Exception if any PKCS#11 operation fails.
    std::vector<CK_BYTE> decrypt_aes_data_on_token(
        CK_SLOT_ID slot_id,
        CK_OBJECT_HANDLE aes_key_handle,
        const std::vector<CK_BYTE>& ciphertext,
        const std::vector<CK_BYTE>& iv);

    // @brief Hash data using SHA-256 on the PKCS#11 token.
    // @param slot_id The ID of the slot to use.
    // @param data The data to be hashed.
    // @return The SHA-256 hash bytes.
    // @throws pkcs11::PKCS11Exception if any PKCS#11 operation fails.
    std::vector<CK_BYTE> hash_sha256_data_on_token(
        CK_SLOT_ID slot_id,
        const std::vector<CK_BYTE>& data);

    // @brief Find a PKCS#11 object by its ID.
    // @param slot_id The ID of the slot to use.
    // @param object_id The ID of the object to find.
    // @return The CK_OBJECT_HANDLE of the found object, or CK_INVALID_HANDLE if not found.
    // @throws pkcs11::PKCS11Exception if the find operation itself fails.
    CK_OBJECT_HANDLE find_object_by_id(
        CK_SLOT_ID slot_id,
        const std::vector<CK_BYTE>& object_id);

    // @brief Destroy a key object on the PKCS#11 token.
    // @param slot_id The ID of the slot to use.
    // @param object_handle The handle of the object to destroy.
    // @throws pkcs11::PKCS11Exception if any PKCS#11 operation fails.
    void destroy_object_on_token(
        CK_SLOT_ID slot_id,
        CK_OBJECT_HANDLE object_handle);

    // @brief Closes the thread-local PKCS#11 session.
    // This should be called by each thread when it finishes its PKCS#11 operations.
    void close_thread_local_session();

private:
    std::string m_pkcs11_library_path;
    std::string m_user_pin;

    // Thread-local storage for sessions.
    // In a real production app, a robust session pool would be more sophisticated.
    static thread_local std::unique_ptr<pkcs11::PKCS11Session> s_thread_session;
    static thread_local CK_SLOT_ID s_thread_session_slot_id;
    static thread_local std::string s_thread_session_pin; // Stored to check if re-login is needed

    // Helper to get or create a thread-local session
    pkcs11::PKCS11Session& get_thread_local_session(CK_SLOT_ID slot_id);
};

} // namespace crypto

#endif // CRYPTO_MANAGER_HPP