cmake_minimum_required(VERSION 3.20)

project(openssl_family_bench VERSION 0.1.0 LANGUAGES C)

include(CTest)

set(OFB_BACKEND "OPENSSL" CACHE STRING "Crypto backend (OPENSSL or LIBRESSL)")
set_property(CACHE OFB_BACKEND PROPERTY STRINGS OPENSSL LIBRESSL)
string(TOUPPER "${OFB_BACKEND}" OFB_BACKEND_UPPER)

if(OFB_BACKEND_UPPER STREQUAL "OPENSSL")
    find_package(OpenSSL REQUIRED COMPONENTS SSL Crypto)
    set(OFB_TARGET ofb-openssl)
    set(OFB_TLS_TARGET ofb-openssl-tls)
    set(OFB_PRIMITIVE_TARGET ofb-openssl-primitives)
    set(OFB_CRYPTO_TARGET OpenSSL::Crypto)
    set(OFB_SSL_TARGET OpenSSL::SSL)
    set(OFB_BACKEND_NAME openssl)
elseif(OFB_BACKEND_UPPER STREQUAL "LIBRESSL")
    find_package(LibreSSL CONFIG REQUIRED COMPONENTS SSL Crypto)
    set(OFB_TARGET ofb-libressl)
    set(OFB_TLS_TARGET ofb-libressl-tls)
    set(OFB_PRIMITIVE_TARGET ofb-libressl-primitives)
    set(OFB_CRYPTO_TARGET LibreSSL::Crypto)
    set(OFB_SSL_TARGET LibreSSL::SSL)
    set(OFB_BACKEND_NAME libressl)
else()
    message(FATAL_ERROR "Unsupported OFB_BACKEND: ${OFB_BACKEND}")
endif()

set(OFB_RESULT_BACKEND "${OFB_BACKEND_NAME}" CACHE STRING
    "Backend label written to benchmark results")
set(OFB_RESULT_ARCHITECTURE "${CMAKE_SYSTEM_PROCESSOR}" CACHE STRING
    "Architecture label written to benchmark results")

add_executable(${OFB_TARGET}
    src/main.c
    src/runner.c
    src/timer.c
    backends/openssl_aead.c
)

add_executable(${OFB_TLS_TARGET}
    src/tls_main.c
    src/timer.c
    backends/openssl_tls.c
)

add_executable(${OFB_PRIMITIVE_TARGET}
    src/primitive_main.c
    src/timer.c
)

target_include_directories(${OFB_TARGET} PRIVATE include)
target_link_libraries(${OFB_TARGET} PRIVATE ${OFB_CRYPTO_TARGET})
target_compile_features(${OFB_TARGET} PRIVATE c_std_11)
target_compile_definitions(${OFB_TARGET} PRIVATE
    OFB_BACKEND_NAME="${OFB_RESULT_BACKEND}"
    OFB_ARCHITECTURE="${OFB_RESULT_ARCHITECTURE}"
)

target_include_directories(${OFB_TLS_TARGET} PRIVATE include)
target_link_libraries(${OFB_TLS_TARGET} PRIVATE
    ${OFB_SSL_TARGET}
    ${OFB_CRYPTO_TARGET}
)
target_compile_features(${OFB_TLS_TARGET} PRIVATE c_std_11)
target_compile_definitions(${OFB_TLS_TARGET} PRIVATE
    OFB_BACKEND_NAME="${OFB_RESULT_BACKEND}"
    OFB_ARCHITECTURE="${OFB_RESULT_ARCHITECTURE}"
    OFB_DEFAULT_CERT_PATH="${CMAKE_CURRENT_SOURCE_DIR}/testdata/server-cert.pem"
    OFB_DEFAULT_KEY_PATH="${CMAKE_CURRENT_SOURCE_DIR}/testdata/server-key.pem"
)

target_include_directories(${OFB_PRIMITIVE_TARGET} PRIVATE include)
target_link_libraries(${OFB_PRIMITIVE_TARGET} PRIVATE ${OFB_CRYPTO_TARGET})
target_compile_features(${OFB_PRIMITIVE_TARGET} PRIVATE c_std_11)
target_compile_definitions(${OFB_PRIMITIVE_TARGET} PRIVATE
    OFB_BACKEND_NAME="${OFB_RESULT_BACKEND}"
    OFB_ARCHITECTURE="${OFB_RESULT_ARCHITECTURE}"
)

if(MSVC)
    target_compile_options(${OFB_TARGET} PRIVATE /W4)
    target_compile_options(${OFB_TLS_TARGET} PRIVATE /W4)
    target_compile_options(${OFB_PRIMITIVE_TARGET} PRIVATE /W4)
else()
    target_compile_options(${OFB_TARGET} PRIVATE -Wall -Wextra -Wpedantic)
    target_compile_options(${OFB_TLS_TARGET} PRIVATE -Wall -Wextra -Wpedantic)
    target_compile_options(${OFB_PRIMITIVE_TARGET} PRIVATE -Wall -Wextra -Wpedantic)
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

    add_test(
        NAME smoke-tls13-handshake
        COMMAND ${OFB_TLS_TARGET} --benchmark handshake
                --cipher TLS_AES_128_GCM_SHA256
                --samples 1 --sample-ms 10 --format jsonl
    )
    set_tests_properties(smoke-tls13-handshake PROPERTIES
        PASS_REGULAR_EXPRESSION "\"benchmark\":\"tls-handshake\""
    )

    add_test(
        NAME smoke-tls13-transfer
        COMMAND ${OFB_TLS_TARGET} --benchmark transfer
                --cipher TLS_AES_128_GCM_SHA256 --size 1024
                --samples 1 --sample-ms 10 --format jsonl
    )
    set_tests_properties(smoke-tls13-transfer PROPERTIES
        PASS_REGULAR_EXPRESSION "\"benchmark\":\"tls-transfer\""
    )

    add_test(
        NAME smoke-sha-256
        COMMAND ${OFB_PRIMITIVE_TARGET} --primitive SHA-256 --operation digest
                --size 64 --sample-ms 10
    )
    set_tests_properties(smoke-sha-256 PROPERTIES
        PASS_REGULAR_EXPRESSION "\"primitive\":\"SHA-256\""
    )

    add_test(
        NAME smoke-aes-128-cbc
        COMMAND ${OFB_PRIMITIVE_TARGET} --primitive AES-128-CBC
                --operation encrypt --size 64 --sample-ms 10
    )
    set_tests_properties(smoke-aes-128-cbc PROPERTIES
        PASS_REGULAR_EXPRESSION "\"primitive\":\"AES-128-CBC\""
    )

    add_test(
        NAME smoke-hmac-sha256
        COMMAND ${OFB_PRIMITIVE_TARGET} --primitive HMAC-SHA256
                --operation mac --size 63 --sample-ms 10
    )
    set_tests_properties(smoke-hmac-sha256 PROPERTIES
        PASS_REGULAR_EXPRESSION "\"primitive\":\"HMAC-SHA256\""
    )
endif()
