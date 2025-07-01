#include "core/crypto_manager.hpp" 
#include "core/pkcs11_wrapper.hpp"
#include <iostream>
#include <thread> // For std::this_thread::get_id
#include <algorithm> // For std::equal

namespace crypto {

// Initialize thread_local static members
thread_local std::unique_ptr<pkcs11::PKCS11Session> CryptoManager::s_thread_session = nullptr;
thread_local CK_SLOT_ID CryptoManager::s_thread_session_slot_id = CK_INVALID_HANDLE;
thread_local std::string CryptoManager::s_thread_session_pin = "";

CryptoManager::CryptoManager(const std::string& pkcs11_library_path, const std::string& user_pin)
    : m_pkcs11_library_path(pkcs11_library_path), m_user_pin(user_pin) {
    // Ensure the PKCS#11 library is initialized globally
    pkcs11::PKCS11Library::get_instance(m_pkcs11_library_path);
    std::cout << "[CryptoManager] Initialized with PKCS#11 library path: " << m_pkcs11_library_path << std::endl;
}

CryptoManager::~CryptoManager() {
    // The PKCS11Library singleton's destructor will handle C_Finalize.
    // No explicit action needed here for global finalization.
    // Any thread-local sessions should be closed by their respective threads.
    if (s_thread_session) {
        std::cerr << "[CryptoManager] Warning: Thread-local session still active in CryptoManager destructor. This should be handled by thread exit." << std::endl;
        s_thread_session.reset(); // Force close if still active
    }
    std::cout << "[CryptoManager] Instance destroyed." << std::endl;
}

CK_SLOT_ID CryptoManager::get_first_slot_id() {
    pkcs11::PKCS11Library& pkcs11_lib = pkcs11::PKCS11Library::get_instance(m_pkcs11_library_path);
    CK_FUNCTION_LIST_PTR funcs = pkcs11_lib.get_function_list();

    CK_ULONG ulSlotCount = 0;
    CK_RV rv = funcs->C_GetSlotList(CK_TRUE, nullptr, &ulSlotCount); // Get count of slots with token
    if (rv != CKR_OK) {
        throw pkcs11::PKCS11Exception("C_GetSlotList (get count) failed", rv);
    }

    if (ulSlotCount == 0) {
        throw std::runtime_error("No PKCS#11 slots with tokens found.");
    }

    std::vector<CK_SLOT_ID> pSlotList(ulSlotCount);
    rv = funcs->C_GetSlotList(CK_TRUE, pSlotList.data(), &ulSlotCount); // Get slot IDs
    if (rv != CKR_OK) {
        throw pkcs11::PKCS11Exception("C_GetSlotList (get list) failed", rv);
    }

    std::cout << "[CryptoManager] Found " << ulSlotCount << " slots. Using first slot ID: " << pSlotList[0] << std::endl;
    return pSlotList[0];
}

pkcs11::PKCS11Session& CryptoManager::get_thread_local_session(CK_SLOT_ID slot_id) {
    // Check if session exists and is for the correct slot/PIN
    if (!s_thread_session || s_thread_session_slot_id != slot_id || s_thread_session_pin != m_user_pin) {
        std::cout << "[Thread " << std::this_thread::get_id() << "] Opening new thread-local session for slot " << slot_id << std::endl;
        s_thread_session = std::make_unique<pkcs11::PKCS11Session>(
            slot_id, CKF_RW_SESSION | CKF_SERIAL_SESSION, m_pkcs11_library_path);
        s_thread_session_slot_id = slot_id;
        s_thread_session_pin = m_user_pin; // Store PIN (sensitive, handle with care in real app)
        s_thread_session->login(CKU_USER, m_user_pin);
    } else {
        std::cout << "[Thread " << std::this_thread::get_id() << "] Reusing existing thread-local session." << std::endl;
        // In a real app, you might want to check session state (C_GetSessionInfo)
        // and re-login if necessary (e.g., CKR_USER_NOT_LOGGED_IN).
        // For this example, we assume the session remains logged in once created.
    }
    return *s_thread_session;
}

void CryptoManager::close_thread_local_session() {
    if (s_thread_session) {
        std::cout << "[Thread " << std::this_thread::get_id() << "] Closing thread-local session." << std::endl;
        try {
            s_thread_session->logout(); // Logout before closing
        } catch (const pkcs11::PKCS11Exception& e) {
            std::cerr << "[Thread " << std::this_thread::get_id() << "] Error during logout: " << e.what() << std::endl;
        }
        s_thread_session.reset(); // This calls the destructor of PKCS11Session
        s_thread_session_slot_id = CK_INVALID_HANDLE;
        s_thread_session_pin.clear(); // Wipe sensitive data
    }
}

std::pair<CK_OBJECT_HANDLE, CK_OBJECT_HANDLE> CryptoManager::generate_rsa_key_pair_on_token(
    CK_SLOT_ID slot_id,
    const std::vector<CK_BYTE>& public_key_id,
    const std::vector<CK_BYTE>& private_key_id,
    CK_ULONG modulus_bits) {

    pkcs11::PKCS11Session& session = get_thread_local_session(slot_id);
    auto key_pair = session.generate_rsa_key_pair(public_key_id, private_key_id, modulus_bits);
    return key_pair;
}

CK_OBJECT_HANDLE CryptoManager::generate_aes_key_on_token(
    CK_SLOT_ID slot_id,
    const std::vector<CK_BYTE>& key_id,
    CK_ULONG key_bits) {

    pkcs11::PKCS11Session& session = get_thread_local_session(slot_id);
    return session.generate_aes_key(key_id, key_bits);
}

std::vector<CK_BYTE> CryptoManager::sign_data_on_token(
    CK_SLOT_ID slot_id,
    CK_OBJECT_HANDLE private_key_handle,
    const std::vector<CK_BYTE>& data) {

    pkcs11::PKCS11Session& session = get_thread_local_session(slot_id);
    auto signature = session.sign_data(private_key_handle, data);
    return signature;
}

bool CryptoManager::verify_signature_on_token(
    CK_SLOT_ID slot_id,
    CK_OBJECT_HANDLE public_key_handle,
    const std::vector<CK_BYTE>& data,
    const std::vector<CK_BYTE>& signature) {

    pkcs11::PKCS11Session& session = get_thread_local_session(slot_id);
    bool verified = session.verify_signature(public_key_handle, data, signature);
    return verified;
}

std::vector<CK_BYTE> CryptoManager::encrypt_rsa_data_on_token(
    CK_SLOT_ID slot_id,
    CK_OBJECT_HANDLE public_key_handle,
    const std::vector<CK_BYTE>& plaintext) {

    pkcs11::PKCS11Session& session = get_thread_local_session(slot_id);
    auto ciphertext = session.encrypt_rsa_data(public_key_handle, plaintext);
    return ciphertext;
}

std::vector<CK_BYTE> CryptoManager::decrypt_rsa_data_on_token(
    CK_SLOT_ID slot_id,
    CK_OBJECT_HANDLE private_key_handle,
    const std::vector<CK_BYTE>& ciphertext) {

    pkcs11::PKCS11Session& session = get_thread_local_session(slot_id);
    auto decrypted_plaintext = session.decrypt_rsa_data(private_key_handle, ciphertext);
    return decrypted_plaintext;
}

std::vector<CK_BYTE> CryptoManager::encrypt_aes_data_on_token(
    CK_SLOT_ID slot_id,
    CK_OBJECT_HANDLE aes_key_handle,
    const std::vector<CK_BYTE>& plaintext,
    const std::vector<CK_BYTE>& iv) {

    pkcs11::PKCS11Session& session = get_thread_local_session(slot_id);
    auto ciphertext = session.encrypt_aes_data(aes_key_handle, plaintext, iv);
    return ciphertext;
}

std::vector<CK_BYTE> CryptoManager::decrypt_aes_data_on_token(
    CK_SLOT_ID slot_id,
    CK_OBJECT_HANDLE aes_key_handle,
    const std::vector<CK_BYTE>& ciphertext,
    const std::vector<CK_BYTE>& iv) {

    pkcs11::PKCS11Session& session = get_thread_local_session(slot_id);
    auto decrypted_plaintext = session.decrypt_aes_data(aes_key_handle, ciphertext, iv);
    return decrypted_plaintext;
}

std::vector<CK_BYTE> CryptoManager::hash_sha256_data_on_token(
    CK_SLOT_ID slot_id,
    const std::vector<CK_BYTE>& data) {

    pkcs11::PKCS11Session& session = get_thread_local_session(slot_id);
    auto hash_value = session.hash_sha256_data(data);
    return hash_value;
}

CK_OBJECT_HANDLE CryptoManager::find_object_by_id(
    CK_SLOT_ID slot_id,
    const std::vector<CK_BYTE>& object_id) {

    pkcs11::PKCS11Session& session = get_thread_local_session(slot_id);

    CK_ATTRIBUTE search_template[] = {
        {CKA_ID, const_cast<CK_BYTE*>(object_id.data()), static_cast<CK_ULONG>(object_id.size())}
    };

    std::vector<CK_OBJECT_HANDLE> found_handles = session.find_objects(
        std::vector<CK_ATTRIBUTE>(search_template, search_template + 1));

    if (!found_handles.empty()) {
        std::cout << "[CryptoManager] Found object with ID '" << std::string(object_id.begin(), object_id.end()) << "': " << found_handles[0] << std::endl;
        return found_handles[0];
    }
    std::cout << "[CryptoManager] Object with ID '" << std::string(object_id.begin(), object_id.end()) << "' not found." << std::endl;
    return CK_INVALID_HANDLE;
}

void CryptoManager::destroy_object_on_token(
    CK_SLOT_ID slot_id,
    CK_OBJECT_HANDLE object_handle) {

    pkcs11::PKCS11Session& session = get_thread_local_session(slot_id);
    session.destroy_object(object_handle);
}

} // namespace crypto