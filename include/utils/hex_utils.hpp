#ifndef HEX_UTILS_HPP
#define HEX_UTILS_HPP

#include <string>
#include <vector>
#include <iomanip> // For std::hex, std::setw, std::setfill
#include <sstream> // For std::stringstream

namespace utils {

// @brief Converts a vector of bytes to a hexadecimal string.
// @param bytes The input vector of bytes.
// @return A string representing the hexadecimal value of the bytes.
inline std::string bytes_to_hex(const std::vector<unsigned char>& bytes) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (unsigned char b : bytes) {
        ss << std::setw(2) << static_cast<int>(b);
    }
    return ss.str();
}

// @brief Converts a hexadecimal string to a vector of bytes.
// @param hex_string The input hexadecimal string.
// @return A vector of bytes.
// @throws std::invalid_argument if the input string has an odd length or invalid hex characters.
inline std::vector<unsigned char> hex_to_bytes(const std::string& hex_string) {
    if (hex_string.length() % 2 != 0) {
        throw std::invalid_argument("Hex string must have an even number of characters.");
    }
    std::vector<unsigned char> bytes;
    bytes.reserve(hex_string.length() / 2);
    for (size_t i = 0; i < hex_string.length(); i += 2) {
        std::string byte_str = hex_string.substr(i, 2);
        bytes.push_back(static_cast<unsigned char>(std::stoul(byte_str, nullptr, 16)));
    }
    return bytes;
}

} // namespace utils

#endif // HEX_UTILS_HPP