# AVXTO Wallet Manager
# Copyright (c) 2026, @REKTBuildr
#
# SPDX-License-Identifier: BSD-3-Clause
# See the LICENSE file in the project root for the full license text.

cmake_minimum_required(VERSION 3.24)

project(AvxtoWalletManager
    VERSION 1.0.0
    DESCRIPTION "AVXTO Wallet Manager - GPG-backed mnemonic wallet manager"
    LANGUAGES CXX)

# ---------------------------------------------------------------------------
# Language level
#
# Qt 6.11 is built and tested against C++23; that is the newest standard Qt
# officially supports (Qt does not yet support C++26). We therefore ask for
# C++23 and refuse to silently fall back.
# ---------------------------------------------------------------------------
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "Build type" FORCE)
endif()

# ---------------------------------------------------------------------------
# Qt
#
# The project targets Qt 6.11.2. The minimum is exposed as a cache variable so
# the tree can also be configured against an older Qt 6 for local smoke
# testing; only APIs available since Qt 6.5 are used.
# ---------------------------------------------------------------------------
set(AVXTO_QT_MIN_VERSION "6.11.2" CACHE STRING
    "Minimum Qt 6 version required to configure the project")

find_package(Qt6 ${AVXTO_QT_MIN_VERSION} REQUIRED COMPONENTS Core Gui Widgets Network)

qt_standard_project_setup()

# ---------------------------------------------------------------------------
# OpenSSL
#
# All in-memory (session) cryptography goes through OpenSSL's libcrypto.
# On macOS the system "openssl" is LibreSSL, which lacks the EVP KDF surface we
# rely on, so prefer a Homebrew/MacPorts OpenSSL 3 when the caller did not pin
# one explicitly.
# ---------------------------------------------------------------------------
if(APPLE AND NOT DEFINED OPENSSL_ROOT_DIR AND NOT DEFINED ENV{OPENSSL_ROOT_DIR})
    foreach(_candidate
            /opt/homebrew/opt/openssl@3
            /usr/local/opt/openssl@3
            /opt/local/libexec/openssl3)
        if(EXISTS "${_candidate}/include/openssl/evp.h")
            set(OPENSSL_ROOT_DIR "${_candidate}")
            message(STATUS "Using OpenSSL from ${OPENSSL_ROOT_DIR}")
            break()
        endif()
    endforeach()
endif()

find_package(OpenSSL 3.0 REQUIRED COMPONENTS Crypto)

# ---------------------------------------------------------------------------
# Target
# ---------------------------------------------------------------------------
qt_add_executable(avxto-wallet-manager
    src/main.cpp
    src/SecureBytes.cpp          src/SecureBytes.h
    src/SessionCrypto.cpp        src/SessionCrypto.h
    src/Bip39.cpp                src/Bip39.h
    src/GpgManager.cpp           src/GpgManager.h
    src/WalletFile.cpp           src/WalletFile.h
    src/WalletSession.cpp        src/WalletSession.h
    src/SessionRegistry.cpp      src/SessionRegistry.h
    src/RpcServer.cpp            src/RpcServer.h
    src/NewWalletDialog.cpp      src/NewWalletDialog.h
    src/MainWindow.cpp           src/MainWindow.h
)

qt_add_resources(avxto-wallet-manager "avxto_resources"
    PREFIX "/"
    BASE "resources"
    FILES
        resources/bip39/english.txt
)

target_include_directories(avxto-wallet-manager PRIVATE src)

target_link_libraries(avxto-wallet-manager PRIVATE
    Qt6::Core
    Qt6::Gui
    Qt6::Widgets
    Qt6::Network
    OpenSSL::Crypto
)

target_compile_definitions(avxto-wallet-manager PRIVATE
    AVXTO_VERSION="${PROJECT_VERSION}"
    QT_NO_CAST_FROM_ASCII
    QT_NO_CAST_TO_ASCII
    QT_DISABLE_DEPRECATED_UP_TO=0x060500
)

if(MSVC)
    target_compile_options(avxto-wallet-manager PRIVATE /W4 /permissive-)
else()
    target_compile_options(avxto-wallet-manager PRIVATE -Wall -Wextra -Wpedantic)
endif()

set_target_properties(avxto-wallet-manager PROPERTIES
    WIN32_EXECUTABLE ON
    MACOSX_BUNDLE ON
    MACOSX_BUNDLE_BUNDLE_NAME "AVXTO Wallet Manager"
    MACOSX_BUNDLE_GUI_IDENTIFIER "to.avax.walletmanager"
    MACOSX_BUNDLE_BUNDLE_VERSION "${PROJECT_VERSION}"
    MACOSX_BUNDLE_SHORT_VERSION_STRING "${PROJECT_VERSION}"
)

include(GNUInstallDirs)
install(TARGETS avxto-wallet-manager
    BUNDLE  DESTINATION .
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

qt_generate_deploy_app_script(
    TARGET avxto-wallet-manager
    OUTPUT_SCRIPT deploy_script
    NO_UNSUPPORTED_PLATFORM_ERROR
)
install(SCRIPT ${deploy_script})
