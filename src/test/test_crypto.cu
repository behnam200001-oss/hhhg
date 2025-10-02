#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <cstring>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include <sstream>
#include <algorithm>
#include "crypto/address_generator.h"

std::string hex_encode(const uint8_t* data, size_t len) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; i++) {
        ss << std::setw(2) << static_cast<unsigned>(data[i]);
    }
    return ss.str();
}

void debug_wif_generation() {
    std::cout << "\n=== DEBUG: WIF Generation Step-by-Step ===\n";
   
    uint8_t private_key[32] = {
        0x18, 0xE1, 0x4A, 0x7B, 0x6A, 0x30, 0x7F, 0x42,
        0x6B, 0x19, 0x8F, 0x3F, 0x87, 0x12, 0x0F, 0x8E,
        0xC3, 0x26, 0x96, 0xFD, 0xBD, 0x22, 0x21, 0x56,
        0xE9, 0x87, 0xCA, 0x41, 0x8A, 0x0B, 0x80, 0x0E
    };
   
    std::cout << "Private Key: " << hex_encode(private_key, 32) << "\n";
   
    std::vector<uint8_t> private_key_reversed(32);
    std::reverse_copy(private_key, private_key + 32, private_key_reversed.begin());
    std::cout << "Private Key (reversed): " << hex_encode(private_key_reversed.data(), 32) << "\n";
   
    std::cout << "\n--- TEST 1: Standard WIF ---\n";
    std::string wif1 = AddressGenerator::private_key_to_wif(private_key, true, false);
    std::cout << "Generated WIF: " << wif1 << "\n";
   
    std::cout << "\n--- TEST 2: Reversed Private Key WIF ---\n";
    std::string wif2 = AddressGenerator::private_key_to_wif(private_key_reversed.data(), true, false);
    std::cout << "Generated WIF (reversed): " << wif2 << "\n";
   
    std::cout << "\n--- TEST 3: Uncompressed WIF ---\n";
    std::string wif3 = AddressGenerator::private_key_to_wif(private_key, false, false);
    std::cout << "Generated WIF (uncompressed): " << wif3 << "\n";
   
    std::cout << "\nExpected WIF: L5kFTk9R6N2FdVBh3o6PgdL2wfgE9bZ6Jf9zE4aZq4bGJvR8qjT\n";
}

void test_with_online_tool_comparison() {
    std::cout << "\n=== COMPARISON WITH ONLINE TOOLS ===\n";
   
    uint8_t private_key[32] = {
        0x18, 0xE1, 0x4A, 0x7B, 0x6A, 0x30, 0x7F, 0x42,
        0x6B, 0x19, 0x8F, 0x3F, 0x87, 0x12, 0x0F, 0x8E,
        0xC3, 0x26, 0x96, 0xFD, 0xBD, 0x22, 0x21, 0x56,
        0xE9, 0x87, 0xCA, 0x41, 0x8A, 0x0B, 0x80, 0x0E
    };
   
    std::cout << "Input this private key hex to online tools:\n";
    std::cout << "18E14A7B6A307F426B198F3F87120F8EC32696FDBD222156E987CA418A0B800E\n\n";
   
    std::cout << "Recommended online tools:\n";
    std::cout << "1. https://www.bitaddress.org/\n";
    std::cout << "2. https://iancoleman.io/bip39/\n";
    std::cout << "3. https://www.mobilefish.com/services/cryptocurrency/cryptocurrency.html\n\n";
   
    std::cout << "Compare the generated WIF with our result.\n";
}

int main() {
    std::cout << "🧪 FINAL CRYPTO DIAGNOSTIC\n";
    std::cout << "===========================\n";
   
    debug_wif_generation();
    test_with_online_tool_comparison();
   
    std::cout << "===========================\n";
    return 0;
}