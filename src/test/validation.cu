#include <iostream>
#include <cassert>
#include "crypto/address_generator.h"

void run_validation_tests() {
    std::cout << "🧪 Running basic validation tests...\n";
   
    assert(AddressGenerator::validate_bitcoin_address("1EJ5q9HAmeVDoZpANqkC5ZRFDG86m4wLBp") == true);
    assert(AddressGenerator::validate_bitcoin_address("invalid") == false);
   
    std::cout << "✅ Basic validation tests completed\n";
}

int main() {
    run_validation_tests();
    return 0;
}