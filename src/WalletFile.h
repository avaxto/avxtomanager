// AVXTO Wallet Manager
// Copyright (c) 2026, @REKTBuildr
//
// SPDX-License-Identifier: BSD-3-Clause
// See the LICENSE file in the project root for the full license text.

#pragma once

#include "SecureBytes.h"

#include <QString>

/*!
 * \brief The plaintext payload that lives inside a GPG-encrypted .bin wallet.
 *
 * Serialised as a small JSON object so a wallet carries its own metadata:
 *
 * \code
 * {"format":"avxto-wallet","version":1,"created":"2026-09-09T12:00:00Z",
 *  "wordCount":24,"mnemonic":"abandon ... art"}
 * \endcode
 *
 * parse() also accepts a file that is nothing but a bare mnemonic, so a
 * wallet exported by another tool (gpg -e over a text file of 24 words) can
 * still be opened here.
 */
namespace WalletFile {

struct Contents
{
    SecureBytes mnemonic; //!< normalised, space-separated words
    QString created;      //!< ISO-8601, empty if the file did not record one
    int wordCount = 0;
    bool checksumValid = false; //!< BIP-39 checksum result, informational
};

//! Builds the JSON payload for a new wallet. The result is in locked memory.
[[nodiscard]] SecureBytes serialise(const SecureBytes &mnemonic);

/*!
 * Reads a decrypted payload. Returns false and sets \a errorOut if no
 * plausible mnemonic could be extracted.
 */
[[nodiscard]] bool parse(const SecureBytes &plaintext, Contents *out, QString *errorOut);

//! True if \a name is a safe single-path-component wallet name (no extension).
[[nodiscard]] bool isValidWalletName(const QString &name, QString *reasonOut = nullptr);

} // namespace WalletFile
