cmake_minimum_required(VERSION 3.20)

project(openssl_family_bench VERSION 0.1.0 LANGUAGES C)

include(CTest)

set(OFB_BACKEND "OPENSSL" CACHE STRING "Crypto backend (OPENSSL or LIBRESSL)")
set_property(CACHE OFB_BACKEND PROPERTY STRINGS OPENSSL LIBRESSL)
string(TOUPPER "${OFB_BACKEND}" OFB_BACKEND_UPPER)

if(OFB_BACKEND_UPPER STREQUAL "OPENSSL")
    find_package(OpenSSL REQUIRED COMPONENTS Crypto)
    set(OFB_TARGET ofb-openssl)
    set(OFB_CRYPTO_TARGET OpenSSL::Crypto)
    set(OFB_BACKEND_NAME openssl)
elseif(OFB_BACKEND_UPPER STREQUAL "LIBRESSL")
    find_package(LibreSSL CONFIG REQUIRED COMPONENTS Crypto)
    set(OFB_TARGET ofb-libressl)
    set(OFB_CRYPTO_TARGET LibreSSL::Crypto)
    set(OFB_BACKEND_NAME libressl)
else()
    message(FATAL_ERROR "Unsupported OFB_BACKEND: ${OFB_BACKEND}")
endif()

add_executable(${OFB_TARGET}
    src/main.c
    src/runner.c
    src/timer.c
    backends/openssl_aead.c
)

target_include_directories(${OFB_TARGET} PRIVATE include)
target_link_libraries(${OFB_TARGET} PRIVATE ${OFB_CRYPTO_TARGET})
target_compile_features(${OFB_TARGET} PRIVATE c_std_11)
target_compile_definitions(${OFB_TARGET} PRIVATE
    OFB_BACKEND_NAME="${OFB_BACKEND_NAME}"
)

if(MSVC)
    target_compile_options(${OFB_TARGET} PRIVATE /W4)
else()
    target_compile_options(${OFB_TARGET} PRIVATE -Wall -Wextra -Wpedantic)
endif()

if(BUILD_TESTING)
    add_test(
        NAME smoke-aes-128-gcm
        COMMAND ${OFB_TARGET} --algorithm AES-128-GCM --operation seal
                --size 64 --samples 1 --sample-ms 10 --format jsonl
    )
    set_tests_properties(smoke-aes-128-gcm PROPERTIES
        PASS_REGULAR_EXPRESSION "\"algorithm\":\"AES-128-GCM\""
    )
endif()
