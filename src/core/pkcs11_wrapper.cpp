#include "core/pkcs11_wrapper.hpp" 
#include <iostream>

#ifdef _WIN32
#include <windows.h> // For LoadLibrary, GetProcAddress, FreeLibrary
#define PKCS11_DLOPEN(path) LoadLibraryA(path.c_str())
#define PKCS11_DLSYM(handle, symbol) GetProcAddress((HMODULE)handle, symbol)
#define PKCS11_DLCLOSE(handle) FreeLibrary((HMODULE)handle)
#else
#include <dlfcn.h> // For dlopen, dlsym, dlclose
#define PKCS11_DLOPEN(path) dlopen(path.c_str(), RTLD_LAZY | RTLD_GLOBAL)
#define PKCS11_DLSYM(handle, symbol) dlsym(handle, symbol)
#define PKCS11_DLCLOSE(handle) dlclose(handle)
#endif

namespace pkcs11 {

// Static members initialization
std::once_flag PKCS11Library::m_init_flag;
std::unique_ptr<PKCS11Library> PKCS11Library::m_instance = nullptr;
std::mutex PKCS11Library::m_instance_mutex;

// --- PKCS11Library Implementation ---

PKCS11Library& PKCS11Library::get_instance(const std::string& library_path) {
    std::call_once(m_init_flag, [&]() {
        if (library_path.empty()) {
            throw std::runtime_error("PKCS11_LIBRARY_PATH must be provided on first call to get_instance.");
        }
        m_instance = std::unique_ptr<PKCS11Library>(new PKCS11Library(library_path));
    });
    return *m_instance;
}

PKCS11Library::PKCS11Library(const std::string& library_path)
    : m_library_handle(nullptr), m_function_list(nullptr) {
    std::cout << "[PKCS11Library] Loading library from: " << library_path << std::endl;
    m_library_handle = PKCS11_DLOPEN(library_path);
    if (!m_library_handle) {
        #ifdef _WIN32
        throw std::runtime_error("Failed to load PKCS#11 library: " + std::to_string(GetLastError()));
        #else
        throw std::runtime_error("Failed to load PKCS#11 library: " + std::string(dlerror()));
        #endif
    }

    CK_C_GetFunctionList get_function_list_ptr =
        (CK_C_GetFunctionList)PKCS11_DLSYM(m_library_handle, "C_GetFunctionList");
    if (!get_function_list_ptr) {
        PKCS11_DLCLOSE(m_library_handle);
        m_library_handle = nullptr;
        #ifdef _WIN32
        throw std::runtime_error("Failed to get C_GetFunctionList: " + std::to_string(GetLastError()));
        #else
        throw std::runtime_error("Failed to get C_GetFunctionList: " + std::string(dlerror()));
        #endif
    }

    CK_RV rv = get_function_list_ptr(&m_function_list);
    if (rv != CKR_OK) {
        PKCS11_DLCLOSE(m_library_handle);
        m_library_handle = nullptr;
        throw PKCS11Exception("C_GetFunctionList failed", rv);
    }

    // Initialize the PKCS#11 library
    rv = m_function_list->C_Initialize(nullptr);
    if (rv != CKR_OK && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED) {
        PKCS11_DLCLOSE(m_library_handle);
        m_library_handle = nullptr;
        throw PKCS11Exception("C_Initialize failed", rv);
    }
    std::cout << "[PKCS11Library] C_Initialize successful." << std::endl;
}

PKCS11Library::~PKCS11Library() {
    if (m_function_list && m_library_handle) {
        CK_RV rv = m_function_list->C_Finalize(nullptr);
        if (rv != CKR_OK) {
            std::cerr << "[PKCS11Library] C_Finalize failed with error: 0x" << std::hex << rv << std::dec << std::endl;
        } else {
            std::cout << "[PKCS11Library] C_Finalize successful." << std::endl;
        }
    }
    if (m_library_handle) {
        PKCS11_DLCLOSE(m_library_handle);
        m_library_handle = nullptr;
        std::cout << "[PKCS11Library] Library handle closed." << std::endl;
    }
}

CK_FUNCTION_LIST_PTR PKCS11Library::get_function_list() const {
    if (!m_function_list) {
        throw std::runtime_error("PKCS#11 library not initialized or function list not available.");
    }
    return m_function_list;
}

// --- PKCS11Session Implementation ---

PKCS11Session::PKCS11Session(CK_SLOT_ID slot_id, CK_FLAGS flags, const std::string& library_path)
    : m_session_handle(CK_INVALID_HANDLE), m_pkcs11_lib(PKCS11Library::get_instance(library_path)) {
    CK_RV rv = m_pkcs11_lib.get_function_list()->C_OpenSession(
        slot_id, flags, nullptr, nullptr, &m_session_handle);
    if (rv != CKR_OK) {
        throw PKCS11Exception("C_OpenSession failed", rv);
    }
    std::cout << "[PKCS11Session] Session opened on slot " << slot_id << ", handle: " << m_session_handle << std::endl;
}

PKCS11Session::~PKCS11Session() {
    if (m_session_handle != CK_INVALID_HANDLE) {
        CK_RV rv = m_pkcs11_lib.get_function_list()->C_CloseSession(m_session_handle);
        if (rv != CKR_OK) {
            std::cerr << "[PKCS11Session] C_CloseSession failed with error: 0x" << std::hex << rv << std::dec << std::endl;
        } else {
            std::cout << "[PKCS11Session] Session " << m_session_handle << " closed." << std::endl;
        }
        m_session_handle = CK_INVALID_HANDLE;
    }
}

void PKCS11Session::login(CK_USER_TYPE user_type, const std::string& pin) {
    std::vector<CK_BYTE> pin_bytes(pin.begin(), pin.end());
    CK_RV rv = m_pkcs11_lib.get_function_list()->C_Login(
        m_session_handle, user_type, pin_bytes.data(), static_cast<CK_ULONG>(pin_bytes.size()));
    secure_erase(pin_bytes.data(), pin_bytes.size()); // Wipe PIN from memory
    if (rv != CKR_OK) {
        throw PKCS11Exception("C_Login failed", rv);
    }
    std::cout << "[PKCS11Session] Logged in to session " << m_session_handle << std::endl;
}

void PKCS11Session::logout() {
    CK_RV rv = m_pkcs11_lib.get_function_list()->C_Logout(m_session_handle);
    if (rv != CKR_OK) {
        throw PKCS11Exception("C_Logout failed", rv);
    }
    std::cout << "[PKCS11Session] Logged out from session " << m_session_handle << std::endl;
}

std::pair<CK_OBJECT_HANDLE, CK_OBJECT_HANDLE> PKCS11Session::generate_rsa_key_pair(
    const std::vector<CK_BYTE>& public_key_id,
    const std::vector<CK_BYTE>& private_key_id,
    CK_ULONG modulus_bits) {

    CK_OBJECT_HANDLE hPublicKey = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE hPrivateKey = CK_INVALID_HANDLE;

    // --- Fix for "lvalue required as unary ‘&’ operand" errors ---
    // Declare temporary variables for the PKCS#11 constants
    CK_OBJECT_CLASS publicKeyClass = CKO_PUBLIC_KEY;
    CK_KEY_TYPE rsaKeyType = CKK_RSA;
    CK_BBOOL ck_true = CK_TRUE;
    CK_BBOOL ck_false = CK_FALSE;
    CK_ULONG public_exponent = 65537; // Common public exponent (0x10001)

    CK_ATTRIBUTE public_key_template[] = {
        {CKA_CLASS, &publicKeyClass, sizeof(publicKeyClass)}, // Use address of variable
        {CKA_KEY_TYPE, &rsaKeyType, sizeof(rsaKeyType)},     // Use address of variable
        {CKA_TOKEN, &ck_true, sizeof(CK_BBOOL)}, // Stored on token
        {CKA_PRIVATE, &ck_false, sizeof(CK_BBOOL)}, // Not private
        {CKA_ENCRYPT, &ck_true, sizeof(CK_BBOOL)},
        {CKA_VERIFY, &ck_true, sizeof(CK_BBOOL)},
        {CKA_WRAP, &ck_true, sizeof(CK_BBOOL)},
        {CKA_MODULUS_BITS, &modulus_bits, sizeof(CK_ULONG)},
        {CKA_PUBLIC_EXPONENT, &public_exponent, sizeof(CK_ULONG)},
        {CKA_ID, const_cast<CK_BYTE*>(public_key_id.data()), static_cast<CK_ULONG>(public_key_id.size())},
        {CKA_LABEL, const_cast<CK_BYTE*>(public_key_id.data()), static_cast<CK_ULONG>(public_key_id.size())} // Use ID as label
    };

    CK_OBJECT_CLASS privateKeyClass = CKO_PRIVATE_KEY; // Declare temporary variable
    // CKK_RSA already declared above

    // Private key template
    CK_ATTRIBUTE private_key_template[] = {
        {CKA_CLASS, &privateKeyClass, sizeof(privateKeyClass)}, // Use address of variable
        {CKA_KEY_TYPE, &rsaKeyType, sizeof(rsaKeyType)},       // Use address of variable
        {CKA_TOKEN, &ck_true, sizeof(CK_BBOOL)}, // Stored on token
        {CKA_PRIVATE, &ck_true, sizeof(CK_BBOOL)}, // Private key
        {CKA_DECRYPT, &ck_true, sizeof(CK_BBOOL)},
        {CKA_SIGN, &ck_true, sizeof(CK_BBOOL)},
        {CKA_UNWRAP, &ck_true, sizeof(CK_BBOOL)},
        {CKA_SENSITIVE, &ck_true, sizeof(CK_BBOOL)}, // Sensitive data
        {CKA_EXTRACTABLE, &ck_false, sizeof(CK_BBOOL)}, // Not extractable
        {CKA_ID, const_cast<CK_BYTE*>(private_key_id.data()), static_cast<CK_ULONG>(private_key_id.size())},
        {CKA_LABEL, const_cast<CK_BYTE*>(private_key_id.data()), static_cast<CK_ULONG>(private_key_id.size())} // Use ID as label
    };

    CK_MECHANISM mechanism = {CKM_RSA_PKCS_KEY_PAIR_GEN, nullptr, 0};

    CK_RV rv = m_pkcs11_lib.get_function_list()->C_GenerateKeyPair(
        m_session_handle,
        &mechanism,
        public_key_template, sizeof(public_key_template) / sizeof(CK_ATTRIBUTE),
        private_key_template, sizeof(private_key_template) / sizeof(CK_ATTRIBUTE),
        &hPublicKey,
        &hPrivateKey
    );

    if (rv != CKR_OK) {
        throw PKCS11Exception("C_GenerateKeyPair failed", rv);
    }
    std::cout << "[PKCS11Session] Generated RSA Key Pair (Public: " << hPublicKey << ", Private: " << hPrivateKey << ")" << std::endl;
    return {hPublicKey, hPrivateKey};
}

CK_OBJECT_HANDLE PKCS11Session::generate_aes_key(
    const std::vector<CK_BYTE>& key_id,
    CK_ULONG key_bits) {

    CK_OBJECT_HANDLE hKey = CK_INVALID_HANDLE;
    CK_BBOOL ck_true = CK_TRUE;
    CK_BBOOL ck_false = CK_FALSE;

    // --- Fix for "lvalue required as unary ‘&’ operand" errors ---
    // Declare temporary variables for the PKCS#11 constants
    CK_OBJECT_CLASS secretKeyClass = CKO_SECRET_KEY;
    CK_KEY_TYPE aesKeyType = CKK_AES;

    CK_ATTRIBUTE aes_key_template[] = {
        {CKA_CLASS, &secretKeyClass, sizeof(secretKeyClass)}, // Use address of variable
        {CKA_KEY_TYPE, &aesKeyType, sizeof(aesKeyType)},     // Use address of variable
        {CKA_TOKEN, &ck_true, sizeof(CK_BBOOL)}, // Stored on token
        {CKA_PRIVATE, &ck_true, sizeof(CK_BBOOL)}, // Private (sensitive)
        {CKA_ENCRYPT, &ck_true, sizeof(CK_BBOOL)},
        {CKA_DECRYPT, &ck_true, sizeof(CK_BBOOL)},
        {CKA_WRAP, &ck_true, sizeof(CK_BBOOL)},
        {CKA_UNWRAP, &ck_true, sizeof(CK_BBOOL)},
        {CKA_VALUE_LEN, &key_bits, sizeof(CK_ULONG)}, // Key length in bits
        {CKA_SENSITIVE, &ck_true, sizeof(CK_BBOOL)}, // Sensitive data
        {CKA_EXTRACTABLE, &ck_false, sizeof(CK_BBOOL)}, // Not extractable
        {CKA_ID, const_cast<CK_BYTE*>(key_id.data()), static_cast<CK_ULONG>(key_id.size())},
        {CKA_LABEL, const_cast<CK_BYTE*>(key_id.data()), static_cast<CK_ULONG>(key_id.size())} // Use ID as label
    };

    CK_MECHANISM mechanism = {CKM_AES_KEY_GEN, nullptr, 0};

    CK_RV rv = m_pkcs11_lib.get_function_list()->C_GenerateKey(
        m_session_handle,
        &mechanism,
        aes_key_template, sizeof(aes_key_template) / sizeof(CK_ATTRIBUTE),
        &hKey
    );

    if (rv != CKR_OK) {
        throw PKCS11Exception("C_GenerateKey (AES) failed", rv);
    }
    std::cout << "[PKCS11Session] Generated AES Key: " << hKey << " (" << key_bits << " bits)" << std::endl;
    return hKey;
}

std::vector<CK_BYTE> PKCS11Session::sign_data(CK_OBJECT_HANDLE private_key_handle, const std::vector<CK_BYTE>& data) {
    CK_MECHANISM mechanism = {CKM_RSA_PKCS, nullptr, 0}; // PKCS#1 v1.5 signing

    CK_RV rv = m_pkcs11_lib.get_function_list()->C_SignInit(
        m_session_handle, &mechanism, private_key_handle);
    if (rv != CKR_OK) {
        throw PKCS11Exception("C_SignInit failed", rv);
    }

    CK_ULONG signature_len = 0;
    rv = m_pkcs11_lib.get_function_list()->C_Sign(
        m_session_handle,
        const_cast<CK_BYTE*>(data.data()), static_cast<CK_ULONG>(data.size()),
        nullptr, &signature_len);
    if (rv != CKR_OK) {
        throw PKCS11Exception("C_Sign (get length) failed", rv);
    }

    std::vector<CK_BYTE> signature(signature_len);
    rv = m_pkcs11_lib.get_function_list()->C_Sign(
        m_session_handle,
        const_cast<CK_BYTE*>(data.data()), static_cast<CK_ULONG>(data.size()),
        signature.data(), &signature_len);
    if (rv != CKR_OK) {
        throw PKCS11Exception("C_Sign failed", rv);
    }
    std::cout << "[PKCS11Session] Data signed successfully. Signature length: " << signature_len << " bytes." << std::endl;
    return signature;
}

bool PKCS11Session::verify_signature(CK_OBJECT_HANDLE public_key_handle, const std::vector<CK_BYTE>& data, const std::vector<CK_BYTE>& signature) {
    CK_MECHANISM mechanism = {CKM_RSA_PKCS, nullptr, 0}; // PKCS#1 v1.5 verification

    CK_RV rv = m_pkcs11_lib.get_function_list()->C_VerifyInit(
        m_session_handle, &mechanism, public_key_handle);
    if (rv != CKR_OK) {
        throw PKCS11Exception("C_VerifyInit failed", rv);
    }

    rv = m_pkcs11_lib.get_function_list()->C_Verify(
        m_session_handle,
        const_cast<CK_BYTE*>(data.data()), static_cast<CK_ULONG>(data.size()),
        const_cast<CK_BYTE*>(signature.data()), static_cast<CK_ULONG>(signature.size()));

    if (rv == CKR_OK) {
        std::cout << "[PKCS11Session] Signature verified successfully." << std::endl;
        return true;
    } else if (rv == CKR_SIGNATURE_INVALID) {
        std::cout << "[PKCS11Session] Signature is invalid." << std::endl;
        return false;
    } else {
        throw PKCS11Exception("C_Verify failed", rv);
    }
}

std::vector<CK_BYTE> PKCS11Session::encrypt_rsa_data(CK_OBJECT_HANDLE public_key_handle, const std::vector<CK_BYTE>& plaintext) {
    CK_MECHANISM mechanism = {CKM_RSA_PKCS, nullptr, 0}; // PKCS#1 v1.5 encryption

    CK_RV rv = m_pkcs11_lib.get_function_list()->C_EncryptInit(
        m_session_handle, &mechanism, public_key_handle);
    if (rv != CKR_OK) {
        throw PKCS11Exception("C_EncryptInit failed", rv);
    }

    CK_ULONG ciphertext_len = 0;
    rv = m_pkcs11_lib.get_function_list()->C_Encrypt(
        m_session_handle,
        const_cast<CK_BYTE*>(plaintext.data()), static_cast<CK_ULONG>(plaintext.size()),
        nullptr, &ciphertext_len);
    if (rv != CKR_OK) {
        throw PKCS11Exception("C_Encrypt (get length) failed", rv);
    }

    std::vector<CK_BYTE> ciphertext(ciphertext_len);
    rv = m_pkcs11_lib.get_function_list()->C_Encrypt(
        m_session_handle,
        const_cast<CK_BYTE*>(plaintext.data()), static_cast<CK_ULONG>(plaintext.size()),
        ciphertext.data(), &ciphertext_len);
    if (rv != CKR_OK) {
        throw PKCS11Exception("C_Encrypt failed", rv);
    }
    std::cout << "[PKCS11Session] Data encrypted (RSA) successfully. Ciphertext length: " << ciphertext_len << " bytes." << std::endl;
    return ciphertext;
}

std::vector<CK_BYTE> PKCS11Session::decrypt_rsa_data(CK_OBJECT_HANDLE private_key_handle, const std::vector<CK_BYTE>& ciphertext) {
    CK_MECHANISM mechanism = {CKM_RSA_PKCS, nullptr, 0}; // PKCS#1 v1.5 decryption

    CK_RV rv = m_pkcs11_lib.get_function_list()->C_DecryptInit(
        m_session_handle, &mechanism, private_key_handle);
    if (rv != CKR_OK) {
        throw PKCS11Exception("C_DecryptInit failed", rv);
    }

    CK_ULONG plaintext_len = 0;
    rv = m_pkcs11_lib.get_function_list()->C_Decrypt(
        m_session_handle,
        const_cast<CK_BYTE*>(ciphertext.data()), static_cast<CK_ULONG>(ciphertext.size()),
        nullptr, &plaintext_len);
    if (rv != CKR_OK) {
        throw PKCS11Exception("C_Decrypt (get length) failed", rv);
    }

    std::vector<CK_BYTE> plaintext(plaintext_len);
    rv = m_pkcs11_lib.get_function_list()->C_Decrypt(
        m_session_handle,
        const_cast<CK_BYTE*>(ciphertext.data()), static_cast<CK_ULONG>(ciphertext.size()),
        plaintext.data(), &plaintext_len);
    if (rv != CKR_OK) {
        throw PKCS11Exception("C_Decrypt failed", rv);
    }
    std::cout << "[PKCS11Session] Data decrypted (RSA) successfully. Plaintext length: " << plaintext_len << " bytes." << std::endl;
    return plaintext;
}

std::vector<CK_BYTE> PKCS11Session::encrypt_aes_data(CK_OBJECT_HANDLE aes_key_handle, const std::vector<CK_BYTE>& plaintext, const std::vector<CK_BYTE>& iv) {
    if (iv.size() != 16) { // AES CBC IV must be 16 bytes
        throw std::invalid_argument("AES CBC IV must be 16 bytes.");
    }
    CK_AES_CBC_PARAMS cbc_params = {0}; // CK_AES_CBC_PARAMS is now defined in pkcs11_wrapper.hpp
    std::copy(iv.begin(), iv.end(), cbc_params.iv);

    CK_MECHANISM mechanism = {CKM_AES_CBC, &cbc_params, sizeof(cbc_params)};

    CK_RV rv = m_pkcs11_lib.get_function_list()->C_EncryptInit(
        m_session_handle, &mechanism, aes_key_handle);
    if (rv != CKR_OK) {
        throw PKCS11Exception("C_EncryptInit (AES) failed", rv);
    }

    CK_ULONG ciphertext_len = 0;
    rv = m_pkcs11_lib.get_function_list()->C_Encrypt(
        m_session_handle,
        const_cast<CK_BYTE*>(plaintext.data()), static_cast<CK_ULONG>(plaintext.size()),
        nullptr, &ciphertext_len);
    if (rv != CKR_OK) {
        throw PKCS11Exception("C_Encrypt (AES, get length) failed", rv);
    }

    std::vector<CK_BYTE> ciphertext(ciphertext_len);
    rv = m_pkcs11_lib.get_function_list()->C_Encrypt(
        m_session_handle,
        const_cast<CK_BYTE*>(plaintext.data()), static_cast<CK_ULONG>(plaintext.size()),
        ciphertext.data(), &ciphertext_len);
    if (rv != CKR_OK) {
        throw PKCS11Exception("C_Encrypt (AES) failed", rv);
    }
    std::cout << "[PKCS11Session] Data encrypted (AES) successfully. Ciphertext length: " << ciphertext_len << " bytes." << std::endl;
    return ciphertext;
}

std::vector<CK_BYTE> PKCS11Session::decrypt_aes_data(CK_OBJECT_HANDLE aes_key_handle, const std::vector<CK_BYTE>& ciphertext, const std::vector<CK_BYTE>& iv) {
    if (iv.size() != 16) { // AES CBC IV must be 16 bytes
        throw std::invalid_argument("AES CBC IV must be 16 bytes.");
    }
    CK_AES_CBC_PARAMS cbc_params = {0}; // CK_AES_CBC_PARAMS is now defined in pkcs11_wrapper.hpp
    std::copy(iv.begin(), iv.end(), cbc_params.iv);

    CK_MECHANISM mechanism = {CKM_AES_CBC, &cbc_params, sizeof(cbc_params)};

    CK_RV rv = m_pkcs11_lib.get_function_list()->C_DecryptInit(
        m_session_handle, &mechanism, aes_key_handle);
    if (rv != CKR_OK) {
        throw PKCS11Exception("C_DecryptInit (AES) failed", rv);
    }

    CK_ULONG plaintext_len = 0;
    rv = m_pkcs11_lib.get_function_list()->C_Decrypt(
        m_session_handle,
        const_cast<CK_BYTE*>(ciphertext.data()), static_cast<CK_ULONG>(ciphertext.size()),
        nullptr, &plaintext_len);
    if (rv != CKR_OK) {
        throw PKCS11Exception("C_Decrypt (AES, get length) failed", rv);
    }

    std::vector<CK_BYTE> plaintext(plaintext_len);
    rv = m_pkcs11_lib.get_function_list()->C_Decrypt(
        m_session_handle,
        const_cast<CK_BYTE*>(ciphertext.data()), static_cast<CK_ULONG>(ciphertext.size()),
        plaintext.data(), &plaintext_len);
    if (rv != CKR_OK) {
        throw PKCS11Exception("C_Decrypt (AES) failed", rv);
    }
    std::cout << "[PKCS11Session] Data decrypted (AES) successfully. Plaintext length: " << plaintext_len << " bytes." << std::endl;
    return plaintext;
}

std::vector<CK_BYTE> PKCS11Session::hash_sha256_data(const std::vector<CK_BYTE>& data) {
    CK_MECHANISM mechanism = {CKM_SHA256, nullptr, 0};

    CK_RV rv = m_pkcs11_lib.get_function_list()->C_DigestInit(m_session_handle, &mechanism);
    if (rv != CKR_OK) {
        throw PKCS11Exception("C_DigestInit (SHA256) failed", rv);
    }

    CK_ULONG hash_len = 0;
    rv = m_pkcs11_lib.get_function_list()->C_Digest(
        m_session_handle,
        const_cast<CK_BYTE*>(data.data()), static_cast<CK_ULONG>(data.size()),
        nullptr, &hash_len);
    if (rv != CKR_OK) {
        throw PKCS11Exception("C_Digest (SHA256, get length) failed", rv);
    }

    std::vector<CK_BYTE> hash_value(hash_len);
    rv = m_pkcs11_lib.get_function_list()->C_Digest(
        m_session_handle,
        const_cast<CK_BYTE*>(data.data()), static_cast<CK_ULONG>(data.size()),
        hash_value.data(), &hash_len);
    if (rv != CKR_OK) {
        throw PKCS11Exception("C_Digest (SHA256) failed", rv);
    }
    std::cout << "[PKCS11Session] Data hashed (SHA256) successfully. Hash length: " << hash_len << " bytes." << std::endl;
    return hash_value;
}

std::vector<CK_OBJECT_HANDLE> PKCS11Session::find_objects(const std::vector<CK_ATTRIBUTE>& attributes) {
    CK_RV rv = m_pkcs11_lib.get_function_list()->C_FindObjectsInit(
        m_session_handle, const_cast<CK_ATTRIBUTE*>(attributes.data()), static_cast<CK_ULONG>(attributes.size()));
    if (rv != CKR_OK) {
        throw PKCS11Exception("C_FindObjectsInit failed", rv);
    }

    std::vector<CK_OBJECT_HANDLE> found_objects;
    CK_OBJECT_HANDLE obj_handle;
    CK_ULONG object_count;
    const CK_ULONG MAX_OBJECTS_TO_FIND_PER_CALL = 10; // Max objects to retrieve in one C_FindObjects call

    do {
        rv = m_pkcs11_lib.get_function_list()->C_FindObjects(
            m_session_handle, &obj_handle, 1, &object_count); // Retrieve one object at a time for simplicity
        if (rv != CKR_OK) {
            m_pkcs11_lib.get_function_list()->C_FindObjectsFinal(m_session_handle);
            throw PKCS11Exception("C_FindObjects failed", rv);
        }
        if (object_count > 0) {
            found_objects.push_back(obj_handle);
        }
    } while (object_count > 0 && found_objects.size() < MAX_OBJECTS_TO_FIND_PER_CALL); // Limit for example

    rv = m_pkcs11_lib.get_function_list()->C_FindObjectsFinal(m_session_handle);
    if (rv != CKR_OK) {
        throw PKCS11Exception("C_FindObjectsFinal failed", rv);
    }
    std::cout << "[PKCS11Session] Found " << found_objects.size() << " objects." << std::endl;
    return found_objects;
}

void PKCS11Session::destroy_object(CK_OBJECT_HANDLE object_handle) {
    CK_RV rv = m_pkcs11_lib.get_function_list()->C_DestroyObject(m_session_handle, object_handle);
    if (rv != CKR_OK) {
        throw PKCS11Exception("C_DestroyObject failed", rv);
    }
    std::cout << "[PKCS11Session] Object " << object_handle << " destroyed." << std::endl;
}

} // namespace pkcs11