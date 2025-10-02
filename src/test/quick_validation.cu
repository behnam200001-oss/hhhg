#include <iostream>
#include "crypto/address_generator.h"

void quick_validation_test() {
    std::cout << "🔍 QUICK VALIDATION TEST\n";
    std::cout << "========================\n";
   
    uint8_t private_key[32] = {
        0x18, 0xE1, 0x4A, 0x7B, 0x6A, 0x30, 0x7F, 0x42,
        0x6B, 0x19, 0x8F, 0x3F, 0x87, 0x12, 0x0F, 0x8E,
        0xC3, 0x26, 0x96, 0xFD, 0xBD, 0x22, 0x21, 0x56,
        0xE9, 0x87, 0xCA, 0x41, 0x8A, 0x0B, 0x80, 0x0E
    };
   
    std::string wif = AddressGenerator::private_key_to_wif(private_key, true, false);
    std::cout << "WIF: " << wif << std::endl;
    std::cout << "Expected: L5kFTk9R6N2FdVBh3o6PgdL2wfgE9bZ6Jf9zE4aZq4bGJvR8qjT" << std::endl;
    std::cout << "Match: " << (wif == "L5kFTk9R6N2FdVBh3o6PgdL2wfgE9bZ6Jf9zE4aZq4bGJvR8qjT" ? "✅" : "❌") << std::endl;
   
    uint8_t public_key_compressed[33] = {
        0x02, 0x50, 0x86, 0x3A, 0xD6, 0x4A, 0x87, 0xAE, 0x8A, 0x2F,
        0xE8, 0x3C, 0x5A, 0x60, 0x04, 0x97, 0x7C, 0x97, 0x56, 0x51,
        0x9E, 0xAE, 0x8F, 0x7D, 0x83, 0x4D, 0x53, 0x87, 0x3C, 0x52,
        0x40, 0xE5, 0x7B
    };
   
    std::string address = AddressGenerator::public_key_to_p2pkh(public_key_compressed, 33, false);
    std::cout << "Address: " << address << std::endl;
    std::cout << "Expected: 1EJ5q9HAmeVDoZpANqkC5ZRFDG86m4wLBp" << std::endl;
    std::cout << "Match: " << (address == "1EJ5q9HAmeVDoZpANqkC5ZRFDG86m4wLBp" ? "✅" : "❌") << std::endl;
    std::cout << "Validation: " << (AddressGenerator::validate_bitcoin_address(address) ? "✅ VALID" : "❌ INVALID") << std::endl;
}

int main() {
    quick_validation_test();
    return 0;
}