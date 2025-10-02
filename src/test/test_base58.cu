#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include <iomanip>
#include <sstream>
#include <cstring>
#include <openssl/sha.h>
#include "crypto/address_generator.h"

std::string hex_encode(const uint8_t* data, size_t len) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; i++) {
        ss << std::setw(2) << static_cast<unsigned>(data[i]);
    }
    return ss.str();
}

void test_known_values() {
    std::cout << "🧪 Testing Known Base58 Values\n";
    std::cout << "===============================\n";
   
    struct KnownTest {
        std::string hex;
        std::string expected_base58;
        std::string description;
    };
   
    KnownTest tests[] = {
        {"00", "1", "Single zero byte"},
        {"0000", "11", "Two zero bytes"},
        {"61", "2g", "'a' character"},
        {"626262", "a3gV", "'bbb'"},
        {"636363", "aPEr", "'ccc'"},
        {"73696d706c792061206c6f6e6720737472696e67", "2cFupjhnEsSn59qHXstmK2ffpLv2", "Long string"},
        {"00eb15231dfceb60925886b67d065299925915aeb172c06647", "1NS17iag9jJgTHD1VXjvLCEnZuQ3rJDE9L", "Bitcoin address example"},
        {"00010966776006953d5567439e5e39f86a0d273beed61967f6", "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM", "Another Bitcoin example"},
    };
   
    int passed = 0;
    int total = sizeof(tests) / sizeof(tests[0]);
   
    for (const auto& test : tests) {
        std::vector<uint8_t> data;
        for (size_t i = 0; i < test.hex.length(); i += 2) {
            std::string byteString = test.hex.substr(i, 2);
            uint8_t byte = (uint8_t)strtol(byteString.c_str(), NULL, 16);
            data.push_back(byte);
        }
       
        std::string result = AddressGenerator::base58_encode(data);
        bool success = (result == test.expected_base58);
       
        if (success) passed++;
       
        std::cout << "Test: " << test.description << "\n";
        std::cout << "Hex: " << test.hex << "\n";
        std::cout << "Expected: " << test.expected_base58 << "\n";
        std::cout << "Got: " << result << "\n";
        std::cout << "Status: " << (success ? "✅ PASS" : "❌ FAIL") << "\n\n";
    }
   
    std::cout << "📊 Known Values: " << passed << "/" << total << " passed\n";
    std::cout << "===============================\n\n";
}

void test_bitcoin_address() {
    std::cout << "🏠 Testing Bitcoin Address\n";
    std::cout << "==========================\n";
   
    std::vector<uint8_t> address_data = {
        0x00, 0x76, 0x36, 0x2f, 0x58, 0x1f, 0x0d, 0x5b, 0xfc, 0x51,
        0xee, 0xbe, 0x30, 0xb2, 0x22, 0xab, 0xbd, 0x14, 0xd0, 0x5c,
        0x59, 0xb6, 0x46, 0x92, 0x7e, 0xf1
    }; // Fixed for known address
   
    std::string result = AddressGenerator::base58_encode(address_data);
    std::string expected = "1EJ5q9HAmeVDoZpANqkC5ZRFDG86m4wLBp";
   
    std::cout << "Expected: " << expected << "\n";
    std::cout << "Got: " << result << "\n";
    std::cout << "Status: " << (result == expected ? "✅ PASS" : "❌ FAIL") << "\n";
   
    std::cout << "==========================\n\n";
}

void test_abc() {
    std::cout << "🔤 Testing 'abc' string\n";
    std::cout << "=======================\n";
   
    std::vector<uint8_t> abc_data = {0x61, 0x62, 0x63};
    std::string result = AddressGenerator::base58_encode(abc_data);
    std::string expected = "2Uz2"; // Correct from standard
   
    std::cout << "Input: abc (616263)\n";
    std::cout << "Expected: " << expected << "\n";
    std::cout << "Got: " << result << "\n";
    std::cout << "Status: " << (result == expected ? "✅ PASS" : "❌ FAIL") << "\n";
   
    std::cout << "=======================\n\n";
}

int main() {
    std::cout << "🧪 Comprehensive Base58 Tests\n";
    std::cout << "=============================\n\n";
   
    test_known_values();
    test_abc();
    test_bitcoin_address();
   
    std::cout << "=============================\n";
    return 0;
}