cmake_minimum_required(VERSION 3.18)
project(BitcoinMiner CUDA CXX)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CUDA_STANDARD 14)
set(CMAKE_CUDA_STANDARD_REQUIRED ON)

set(CMAKE_CUDA_ARCHITECTURES 70 75 80 86 89)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBSECP256K1 REQUIRED libsecp256k1)
if(NOT LIBSECP256K1_FOUND)
    message(WARNING "libsecp256k1 not found, hybrid processing will be disabled")
    set(LIBSECP256K1_INCLUDE_DIRS "")
    set(LIBSECP256K1_LIBRARIES "")
endif()

find_package(CUDAToolkit REQUIRED)
find_package(OpenSSL REQUIRED)

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/src/crypto
    ${CMAKE_CURRENT_SOURCE_DIR}/src/bloom
    ${CMAKE_CURRENT_SOURCE_DIR}/src/utils
    ${CMAKE_CURRENT_SOURCE_DIR}/src/profiling
    ${CMAKE_CURRENT_SOURCE_DIR}/kernels
    ${LIBSECP256K1_INCLUDE_DIRS}
)

set(SOURCES
    src/main.cu
    src/cuda_miner.cu
    src/crypto/address_generator.cu
    src/crypto/hash_wrapper.cu
    src/crypto/secp256k1_wrapper.cu
    src/crypto/hybrid_processor.cu
    src/bloom/gpu_bloom.cu
    src/utils/memory_manager.cu
    src/profiling/nvtx_helpers.cu
    kernels/mining_kernels.cu
)

set(TEST_SOURCES
    src/test/address_generator.cu
    src/test/quick_validation.cu
    src/test/simple_validation.cu
    src/test/test_address_generation.cu
    src/test/test_base58.cu
    src/test/test_crypto.cu
    src/test/validation.cu
)

add_executable(bitcoin_miner ${SOURCES})

target_link_libraries(bitcoin_miner
    PRIVATE
    CUDA::cudart
    CUDA::curand
    OpenSSL::Crypto
    OpenSSL::SSL
    ${LIBSECP256K1_LIBRARIES}
    Threads::Threads
)

set_target_properties(bitcoin_miner PROPERTIES
    CUDA_RUNTIME_LIBRARY Shared
    CUDA_ARCHITECTURES "${CMAKE_CUDA_ARCHITECTURES}"
    CUDA_SEPARABLE_COMPILATION ON
)

target_compile_options(bitcoin_miner PRIVATE
    $<$<COMPILE_LANGUAGE:CUDA>:-std=c++14 --expt-relaxed-constexpr --expt-extended-lambda>
    $<$<COMPILE_LANGUAGE:CXX>:-std=c++14 -O3 -march=native>
    $<$<CONFIG:Release>:-O3 -DNDEBUG>
    $<$<CONFIG:Debug>:-g -O0 -DDEBUG>
)

add_executable(test_bitcoin_miner ${TEST_SOURCES})

target_link_libraries(test_bitcoin_miner
    PRIVATE
    CUDA::cudart
    CUDA::curand
    OpenSSL::Crypto
    OpenSSL::SSL
    ${LIBSECP256K1_LIBRARIES}
    Threads::Threads
)

set_target_properties(test_bitcoin_miner PROPERTIES
    CUDA_RUNTIME_LIBRARY Shared
    CUDA_ARCHITECTURES "${CMAKE_CUDA_ARCHITECTURES}"
)

add_custom_target(run_tests
    COMMAND ./test_bitcoin_miner
    DEPENDS test_bitcoin_miner
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    COMMENT "Running Bitcoin miner tests..."
)

install(TARGETS bitcoin_miner
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)

message(STATUS "==============================================")
message(STATUS "Bitcoin Miner Build Configuration:")
message(STATUS " CUDA Architectures: ${CMAKE_CUDA_ARCHITECTURES}")
message(STATUS " OpenSSL Found: ${OPENSSL_FOUND}")
message(STATUS " libsecp256k1 Found: ${LIBSECP256K1_FOUND}")
message(STATUS " Build Type: ${CMAKE_BUILD_TYPE}")
message(STATUS "==============================================")