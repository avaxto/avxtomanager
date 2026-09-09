// AVXTO Wallet Manager
// Copyright (c) 2026, @REKTBuildr
//
// SPDX-License-Identifier: BSD-3-Clause
// See the LICENSE file in the project root for the full license text.

#pragma once

#include "SecureBytes.h"

#include <QByteArray>
#include <QString>

#include <optional>

/*!
 * \brief In-memory ("session") cryptography, implemented entirely with OpenSSL.
 *
 * Every wallet that is unlocked in the GUI keeps its mnemonic only as an
 * AES-256-GCM sealed blob. The key is derived from a per-wallet session
 * password that is generated fresh each time the wallet is opened.
 *
 * Authentication is a side effect of decryption: a wrong password fails the
 * GCM tag check, so the RPC layer never has to compare passwords itself and
 * there is no separate verifier to leak.
 */
namespace SessionCrypto {

//! AES-256 key length.
inline constexpr int kKeyBytes = 32;
//! GCM nonce length; 96 bits is the size the mode is defined for.
inline constexpr int kIvBytes = 12;
inline constexpr int kTagBytes = 16;
inline constexpr int kSaltBytes = 16;

/*!
 * PBKDF2 work factor.
 *
 * Session passwords are 256 bits of CSPRNG output, so a single-pass KDF would
 * already be sound; the iteration count is margin in case a password is ever
 * shortened for usability, and it is small enough (~40 ms) to run inline on an
 * RPC request without a perceptible stall.
 */
inline constexpr int kPbkdf2Iterations = 100000;

//! Cryptographically secure random bytes. Throws CryptoError on RNG failure.
[[nodiscard]] SecureBytes randomBytes(std::size_t count);

/*!
 * Generates a session password: 32 random bytes rendered as unpadded
 * base64url, i.e. 43 characters that survive copy/paste, shell quoting and
 * JSON without escaping.
 */
[[nodiscard]] SecureBytes generateSessionPassword();

//! Seals \a plaintext under \a password. Returns a self-describing blob.
[[nodiscard]] QByteArray seal(const SecureBytes &plaintext, const SecureBytes &password);

/*!
 * Opens a blob produced by seal(). Returns nullopt for a wrong password, a
 * truncated blob or any other tampering — the caller cannot and should not
 * distinguish these cases.
 */
[[nodiscard]] std::optional<SecureBytes> open(const QByteArray &blob, const SecureBytes &password);

//! Thrown when OpenSSL itself fails (allocation, RNG, engine errors).
class CryptoError
{
public:
    explicit CryptoError(QString message) : m_message(std::move(message)) {}
    [[nodiscard]] const QString &message() const noexcept { return m_message; }

private:
    QString m_message;
};

} // namespace SessionCrypto
