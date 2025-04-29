cmake_minimum_required(VERSION 3.15)
project(SecurePassManager VERSION 1.2.0 LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Build type
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Platform detection
set(IS_WINDOWS 0)
set(IS_MACOS 0)
set(IS_IOS 0)
set(IS_ANDROID 0)
set(IS_LINUX 0)
set(IS_RASPBERRY_PI 0)

if(APPLE)
    if(CMAKE_SYSTEM_NAME STREQUAL "iOS")
        set(IS_IOS 1)
    else()
        set(IS_MACOS 1)
    endif()
elseif(ANDROID)
    set(IS_ANDROID 1)
elseif(WIN32)
    set(IS_WINDOWS 1)
elseif(CMAKE_SYSTEM_NAME MATCHES "Linux")
    set(IS_LINUX 1)
    # Check for Raspberry Pi
    if(EXISTS "/proc/cpuinfo")
        execute_process(
            COMMAND grep -q "Raspberry Pi" /proc/cpuinfo
            RESULT_VARIABLE NOT_RPI
            OUTPUT_QUIET
            ERROR_QUIET
        )
        if(NOT_RPI EQUAL 0)
            set(IS_RASPBERRY_PI 1)
        endif()
    endif()
endif()

# Security flags
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wpedantic -fstack-protector-strong")
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O2 -D_FORTIFY_SOURCE=2")
elseif(MSVC)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W4 /sdl /guard:cf")
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /O2 /GL")
endif()

# Find required packages
find_package(OpenSSL REQUIRED)
find_package(SQLite3 REQUIRED)
find_package(Threads REQUIRED)

# Optional packages for advanced features
find_package(Argon2 QUIET)
if(Argon2_FOUND)
    set(Argon2_FOUND 1)
else()
    set(Argon2_FOUND 0)
endif()

find_package(Botan QUIET)
if(Botan_FOUND)
    set(Botan_FOUND 1)
else()
    set(Botan_FOUND 0)
endif()

find_package(libsodium QUIET)
if(libsodium_FOUND)
    set(libsodium_FOUND 1)
else()
    set(libsodium_FOUND 0)
endif()

find_package(ZLIB QUIET)

# Optional GUI support
option(ENABLE_GUI "Enable GUI support" OFF)
set(HAVE_QT 0)
if(ENABLE_GUI)
    find_package(Qt5 COMPONENTS Widgets QUIET)
    if(Qt5_FOUND)
        set(HAVE_QT 1)
    endif()
endif()

# Optional mobile support
option(ENABLE_MOBILE "Enable mobile device support" OFF)
set(HAVE_MOBILE_SUPPORT 0)
if(ENABLE_MOBILE)
    if(IS_ANDROID OR IS_IOS)
        set(HAVE_MOBILE_SUPPORT 1)
    endif()
endif()

# Optional hardware security module support
option(ENABLE_HSM "Enable Hardware Security Module support" OFF)
set(HAVE_HSM 0)
if(ENABLE_HSM)
    find_package(PKCS11 QUIET)
    if(PKCS11_FOUND)
        set(HAVE_HSM 1)
    endif()
endif()

# Optional biometric support
option(ENABLE_BIOMETRICS "Enable biometric authentication" OFF)
set(HAVE_WINDOWS_BIOMETRIC_FRAMEWORK 0)
set(HAVE_TOUCH_ID 0)
set(HAVE_ANDROID_BIOMETRICS 0)
if(ENABLE_BIOMETRICS)
    if(IS_WINDOWS)
        set(HAVE_WINDOWS_BIOMETRIC_FRAMEWORK 1)
    elseif(IS_MACOS OR IS_IOS)
        set(HAVE_TOUCH_ID 1)
    elseif(IS_ANDROID)
        set(HAVE_ANDROID_BIOMETRICS 1)
    endif()
endif()

# Optional cloud sync support
option(ENABLE_CLOUD_SYNC "Enable cloud synchronization" OFF)
set(HAVE_CLOUD_SYNC 0)
if(ENABLE_CLOUD_SYNC)
    find_package(CURL REQUIRED)
    find_package(nlohmann_json QUIET)
    if(CURL_FOUND)
        set(HAVE_CLOUD_SYNC 1)
    endif()
endif()

# Optional YubiKey support
option(ENABLE_YUBIKEY "Enable YubiKey support" OFF)
set(HAVE_YUBIKEY 0)
if(ENABLE_YUBIKEY)
    find_package(YubiKey QUIET)
    if(YubiKey_FOUND)
        set(HAVE_YUBIKEY 1)
    endif()
endif()

# Configuration options based on available packages
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/config.h.in
    ${CMAKE_CURRENT_BINARY_DIR}/include/config.h
)

# Include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_BINARY_DIR}/include
    ${OPENSSL_INCLUDE_DIR}
    ${SQLite3_INCLUDE_DIRS}
)

# List core source files
set(CORE_SOURCES
    src/encryption.cpp
    src/enhanced_security.cpp
    src/database.cpp
    src/passwordmanager.cpp
    src/cli.cpp
    src/password_generator.cpp
    src/password_strength.cpp
    src/authenticator.cpp
    src/aes_gcm.cpp
    src/kdf_argon2.cpp
    src/compression.cpp
    src/secure_memory.cpp
)

# Add all source files
file(GLOB_RECURSE ADDITIONAL_SOURCES "src/*.cpp")
list(REMOVE_ITEM ADDITIONAL_SOURCES ${CORE_SOURCES})

# Main executable
add_executable(securepass 
    ${CORE_SOURCES}
    ${ADDITIONAL_SOURCES}
    src/main.cpp
)

# Test executable
if(BUILD_TESTING)
    add_executable(security_test
        test/enhanced_security_test.cpp
        ${CORE_SOURCES}
    )
    
    target_link_libraries(security_test
        ${OPENSSL_LIBRARIES}
        ${SQLite3_LIBRARIES}
        Threads::Threads
    )
    
    if(Argon2_FOUND)
        target_link_libraries(security_test Argon2::Argon2)
    endif()
    
    if(libsodium_FOUND)
        target_link_libraries(security_test ${libsodium_LIBRARIES})
    endif()
    
    if(ZLIB_FOUND)
        target_link_libraries(security_test ZLIB::ZLIB)
    endif()
endif()

# Link libraries
target_link_libraries(securepass 
    ${OPENSSL_LIBRARIES}
    ${SQLite3_LIBRARIES}
    Threads::Threads
)

# Add optional libraries if available
if(Argon2_FOUND)
    target_link_libraries(securepass Argon2::Argon2)
endif()

if(Botan_FOUND)
    target_link_libraries(securepass Botan::Botan)
endif()

if(libsodium_FOUND)
    target_link_libraries(securepass ${libsodium_LIBRARIES})
endif()

if(ZLIB_FOUND)
    target_link_libraries(securepass ZLIB::ZLIB)
endif()

if(HAVE_QT)
    target_link_libraries(securepass Qt5::Widgets)
endif()

if(HAVE_CLOUD_SYNC)
    target_link_libraries(securepass ${CURL_LIBRARIES})
    if(TARGET nlohmann_json::nlohmann_json)
        target_link_libraries(securepass nlohmann_json::nlohmann_json)
    endif()
endif()

if(HAVE_HSM)
    target_link_libraries(securepass ${PKCS11_LIBRARIES})
endif()

if(HAVE_YUBIKEY)
    target_link_libraries(securepass ${YUBIKEY_LIBRARIES})
endif()

# Versioning
set_target_properties(securepass PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
)

# Installation
install(TARGETS securepass DESTINATION bin)

# Documentation
option(BUILD_DOCUMENTATION "Build documentation" OFF)
if(BUILD_DOCUMENTATION)
    find_package(Doxygen)
    if(DOXYGEN_FOUND)
        set(DOXYGEN_IN ${CMAKE_CURRENT_SOURCE_DIR}/docs/Doxyfile.in)
        set(DOXYGEN_OUT ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile)
        
        configure_file(${DOXYGEN_IN} ${DOXYGEN_OUT} @ONLY)
        
        add_custom_target(doc
            COMMAND ${DOXYGEN_EXECUTABLE} ${DOXYGEN_OUT}
            WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
            COMMENT "Generating API documentation with Doxygen"
            VERBATIM
        )
    else()
        message(STATUS "Doxygen not found, documentation will not be built")
    endif()
endif()

# Testing
option(BUILD_TESTING "Build tests" ON)
if(BUILD_TESTING)
    enable_testing()
    add_subdirectory(test)
endif()

# Package generation
set(CPACK_PACKAGE_NAME "securepass")
set(CPACK_PACKAGE_VENDOR "SNO7E")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Secure Password Manager - Advanced CLI Password Management")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_VERSION_MAJOR ${PROJECT_VERSION_MAJOR})
set(CPACK_PACKAGE_VERSION_MINOR ${PROJECT_VERSION_MINOR})
set(CPACK_PACKAGE_VERSION_PATCH ${PROJECT_VERSION_PATCH})
set(CPACK_PACKAGE_CONTACT "Mahmoud Ashraf (SNO7E)")

# Platform-specific packaging
if(IS_WINDOWS)
    set(CPACK_GENERATOR "NSIS")
    set(CPACK_NSIS_ENABLE_UNINSTALL_BEFORE_INSTALL ON)
    set(CPACK_NSIS_MODIFY_PATH ON)
elseif(IS_MACOS)
    set(CPACK_GENERATOR "DragNDrop")
elseif(IS_LINUX)
    set(CPACK_GENERATOR "DEB;RPM")
    set(CPACK_DEBIAN_PACKAGE_DEPENDS "libssl-dev, libsqlite3-dev")
    set(CPACK_RPM_PACKAGE_REQUIRES "openssl-devel, sqlite-devel")
endif()

include(CPack) 