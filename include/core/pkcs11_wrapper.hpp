#ifndef PKCS11_WRAPPER_HPP
#define PKCS11_WRAPPER_HPP

#include <string>
#include <vector>
#include <memory>
#include <stdexcept>
#include <mutex>
#include <functional> // For std::function
#include <algorithm>  // For std::fill

// Include PKCS#11 header. Ensure this path is correct for your system.
// On Ubuntu, this is typically provided by `libsofthsm2-dev` package.
#include <pkcs11.h>

// --- Explicitly define CK_AES_CBC_PARAMS if not already defined ---
// Some PKCS#11 headers might not define this structure explicitly or define it conditionally.
// This ensures it's always available for AES CBC operations.
#ifndef CK_AES_CBC_PARAMS
typedef struct CK_AES_CBC_PARAMS {
    CK_BYTE iv[16];
} CK_AES_CBC_PARAMS;
#endif

namespace pkcs11 {

// --- Utility for secure memory erasure ---
// This is a basic attempt. For true security, consider OS-specific secure memory APIs.
inline void secure_erase(void* ptr, size_t len) {
    if (ptr && len > 0) {
        volatile unsigned char* vptr = static_cast<volatile unsigned char*>(ptr);
        std::fill(vptr, vptr + len, 0);
    }
}

// --- Custom Exception for PKCS#11 Errors ---
class PKCS11Exception : public std::runtime_error {
public:
    // @brief Constructor for PKCS11Exception.
    // @param message A descriptive error message.
    // @param rv The PKCS#11 return value (CK_RV) that caused the exception.
    explicit PKCS11Exception(const std::string& message, CK_RV rv)
        : std::runtime_error(message + " (PKCS#11 Error: 0x" + to_hex_string(rv) + ")"),
          m_rv(rv) {}

    // @brief Get the raw PKCS#11 return value.
    // @return The CK_RV value.
    CK_RV get_return_value() const noexcept { return m_rv; }

private:
    CK_RV m_rv;
    // Helper to convert CK_RV to hex string for error messages
    static std::string to_hex_string(CK_RV rv) {
        char buf[10];
        snprintf(buf, sizeof(buf), "%lX", static_cast<unsigned long>(rv));
        return std::string(buf);
    }
};

// --- PKCS#11 Library Management (Singleton) ---
class PKCS11Library {
public:
    // @brief Get the singleton instance of the PKCS11Library.
    // @param library_path The path to the PKCS#11 shared library (e.g., "/usr/lib/softhsm/libsofthsm2.so").
    //                     This parameter is only used during the first call to initialize the library.
    // @return A reference to the PKCS11Library instance.
    static PKCS11Library& get_instance(const std::string& library_path = "");

    // @brief Destructor. Calls C_Finalize if the library was initialized.
    ~PKCS11Library();

    // @brief Get the PKCS#11 function list.
    // @return A pointer to the CK_FUNCTION_LIST structure.
    // @throws PKCS11Exception if the library is not initialized or function list is not available.
    CK_FUNCTION_LIST_PTR get_function_list() const;

    // Delete copy constructor and assignment operator to prevent copying
    PKCS11Library(const PKCS11Library&) = delete;
    PKCS11Library& operator=(const PKCS11Library&) = delete;

private:
    // Private constructor for singleton pattern.
    // @param library_path The path to the PKCS#11 shared library.
    explicit PKCS11Library(const std::string& library_path);

    // Handle to the dynamically loaded PKCS#11 library
    void* m_library_handle;
    // Pointer to the PKCS#11 function list
    CK_FUNCTION_LIST_PTR m_function_list;
    // Mutex for thread-safe initialization/finalization
    static std::once_flag m_init_flag;
    static std::unique_ptr<PKCS11Library> m_instance;
    static std::mutex m_instance_mutex; // For thread-safe instance creation
};

// --- RAII Wrapper for PKCS#11 Session ---
class PKCS11Session {
public:
    // @brief Constructor. Opens a new PKCS#11 session.
    // @param slot_id The ID of the slot to open the session on.
    // @param flags Flags for session opening (e.g., CKF_RW_SESSION | CKF_SERIAL_SESSION).
    // @param library_path The path to the PKCS#11 library. Used to ensure library is initialized.
    // @throws PKCS11Exception if session opening fails.
    PKCS11Session(CK_SLOT_ID slot_id, CK_FLAGS flags, const std::string& library_path);

    // @brief Destructor. Closes the PKCS#11 session.
    ~PKCS11Session();

    // @brief Get the session handle.
    // @return The CK_SESSION_HANDLE.
    CK_SESSION_HANDLE get_handle() const noexcept { return m_session_handle; }

    // @brief Log in to the session.
    // @param user_type The user type (e.g., CKU_USER, CKU_SO).
    // @param pin The PIN for the user.
    // @throws PKCS11Exception if login fails.
    void login(CK_USER_TYPE user_type, const std::string& pin);

    // @brief Log out from the session.
    // @throws PKCS11Exception if logout fails.
    void logout();

    // @brief Generate an RSA key pair on the token.
    // @param public_key_id ID for the public key object.
    // @param private_key_id ID for the private key object.
    // @param modulus_bits The desired modulus size in bits (e.g., 2048).
    // @return A pair of CK_OBJECT_HANDLEs: {public_key_handle, private_key_handle}.
    // @throws PKCS11Exception if key generation fails.
    std::pair<CK_OBJECT_HANDLE, CK_OBJECT_HANDLE> generate_rsa_key_pair(
        const std::vector<CK_BYTE>& public_key_id,
        const std::vector<CK_BYTE>& private_key_id,
        CK_ULONG modulus_bits);

    // @brief Generate an AES symmetric key on the token.
    // @param key_id ID for the key object.
    // @param key_bits The desired key size in bits (e.g., 128, 256).
    // @return The CK_OBJECT_HANDLE of the generated AES key.
    // @throws PKCS11Exception if key generation fails.
    CK_OBJECT_HANDLE generate_aes_key(
        const std::vector<CK_BYTE>& key_id,
        CK_ULONG key_bits);

    // @brief Sign data using a private key on the token.
    // @param private_key_handle The handle of the private key object.
    // @param data The data to be signed.
    // @return The signature bytes.
    // @throws PKCS11Exception if signing fails.
    std::vector<CK_BYTE> sign_data(CK_OBJECT_HANDLE private_key_handle, const std::vector<CK_BYTE>& data);

    // @brief Verify a signature using a public key on the token.
    // @param public_key_handle The handle of the public key object.
    // @param data The original data that was signed.
    // @param signature The signature to verify.
    // @return True if the signature is valid, false otherwise.
    // @throws PKCS11Exception if verification fails (other than CKR_SIGNATURE_INVALID).
    bool verify_signature(CK_OBJECT_HANDLE public_key_handle, const std::vector<CK_BYTE>& data, const std::vector<CK_BYTE>& signature);

    // @brief Encrypt data using a public key on the token.
    // @param public_key_handle The handle of the public key object.
    // @param plaintext The data to be encrypted.
    // @return The ciphertext bytes.
    // @throws PKCS11Exception if encryption fails.
    std::vector<CK_BYTE> encrypt_rsa_data(CK_OBJECT_HANDLE public_key_handle, const std::vector<CK_BYTE>& plaintext);

    // @brief Decrypt data using a private key on the token.
    // @param private_key_handle The handle of the private key object.
    // @param ciphertext The data to be decrypted.
    // @return The decrypted plaintext bytes.
    // @throws PKCS11Exception if decryption fails.
    std::vector<CK_BYTE> decrypt_rsa_data(CK_OBJECT_HANDLE private_key_handle, const std::vector<CK_BYTE>& ciphertext);

    // @brief Encrypt data using a symmetric key (AES CBC) on the token.
    // @param aes_key_handle The handle of the AES key object.
    // @param plaintext The data to be encrypted.
    // @param iv The initialization vector (must be 16 bytes for AES CBC).
    // @return The ciphertext bytes.
    // @throws PKCS11Exception if encryption fails.
    std::vector<CK_BYTE> encrypt_aes_data(CK_OBJECT_HANDLE aes_key_handle, const std::vector<CK_BYTE>& plaintext, const std::vector<CK_BYTE>& iv);

    // @brief Decrypt data using a symmetric key (AES CBC) on the token.
    // @param aes_key_handle The handle of the AES key object.
    // @param ciphertext The data to be decrypted.
    // @param iv The initialization vector (must be 16 bytes for AES CBC).
    // @return The decrypted plaintext bytes.
    // @throws PKCS11Exception if decryption fails.
    std::vector<CK_BYTE> decrypt_aes_data(CK_OBJECT_HANDLE aes_key_handle, const std::vector<CK_BYTE>& ciphertext, const std::vector<CK_BYTE>& iv);

    // @brief Hash data using SHA-256 on the token.
    // @param data The data to be hashed.
    // @return The SHA-256 hash bytes.
    // @throws PKCS11Exception if hashing fails.
    std::vector<CK_BYTE> hash_sha256_data(const std::vector<CK_BYTE>& data);

    // @brief Find a PKCS#11 object.
    // @param attributes A vector of CK_ATTRIBUTE structures to match.
    // @return A vector of CK_OBJECT_HANDLEs found.
    // @throws PKCS11Exception if finding objects fails.
    std::vector<CK_OBJECT_HANDLE> find_objects(const std::vector<CK_ATTRIBUTE>& attributes);

    // @brief Destroy a PKCS#11 object.
    // @param object_handle The handle of the object to destroy.
    // @throws PKCS11Exception if destroying the object fails.
    void destroy_object(CK_OBJECT_HANDLE object_handle);

    // Delete copy constructor and assignment operator
    PKCS11Session(const PKCS11Session&) = delete;
    PKCS11Session& operator=(const PKCS11Session&) = delete;

private:
    CK_SESSION_HANDLE m_session_handle;
    PKCS11Library& m_pkcs11_lib; // Reference to the initialized PKCS#11 library
};

} // namespace pkcs11

#endif // PKCS11_WRAPPER_HPP