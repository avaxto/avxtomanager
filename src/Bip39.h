// AVXTO Wallet Manager
// Copyright (c) 2026, @REKTBuildr
//
// SPDX-License-Identifier: BSD-3-Clause
// See the LICENSE file in the project root for the full license text.

#pragma once

#include "SecureBytes.h"

#include <QString>
#include <QStringList>

/*!
 * \brief BIP-39 English mnemonic generation and validation.
 *
 * Only the 24-word (256-bit entropy) form is generated, which is what this
 * application is for; validation accepts any of the standard lengths so a
 * wallet file written elsewhere still loads.
 *
 * Entropy comes from OpenSSL's RAND_bytes, the same CSPRNG used for session
 * keys — there is no second, weaker source anywhere in the program.
 */
namespace Bip39 {

inline constexpr int kWordCount = 24;
inline constexpr int kEntropyBytes = 32;

//! The 2048-word English list, loaded once from the compiled-in resource.
[[nodiscard]] const QStringList &wordlist();

/*!
 * Generates a fresh 24-word mnemonic. The result lives in locked memory and
 * is never written anywhere by this function.
 *
 * \throws SessionCrypto::CryptoError if the RNG fails.
 * \throws std::runtime_error if the bundled wordlist is missing or corrupt.
 */
[[nodiscard]] SecureBytes generateMnemonic();

//! True if \a mnemonic has a valid length, known words and a correct checksum.
[[nodiscard]] bool validate(const QString &mnemonic);

//! Splits on any run of whitespace, normalising to lowercase single spaces.
[[nodiscard]] QStringList splitWords(const QString &mnemonic);

//! Canonical form: lowercase words joined by single spaces.
[[nodiscard]] QString normalise(const QString &mnemonic);

} // namespace Bip39
