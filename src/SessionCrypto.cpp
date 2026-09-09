// AVXTO Wallet Manager
// Copyright (c) 2026, @REKTBuildr
//
// SPDX-License-Identifier: BSD-3-Clause
// See the LICENSE file in the project root for the full license text.

#include "SessionCrypto.h"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <cstring>
#include <memory>

namespace SessionCrypto {
namespace {

//! Blob header: magic + version. Authenticated as GCM additional data.
constexpr char kMagic[4] = {'A', 'V', 'X', 'S'};
constexpr quint8 kVersion = 1;
constexpr int kHeaderBytes = sizeof(kMagic) + 1 + kSaltBytes + kIvBytes;

using CipherCtx = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;

QString lastOpenSslError()
{
    const unsigned long code = ERR_get_error();
    if (code == 0)
        return QStringLiteral("unknown OpenSSL error");

    char buffer[256] = {};
    ERR_error_string_n(code, buffer, sizeof(buffer));
    ERR_clear_error();
    return QString::fromLatin1(buffer);
}

/*!
 * Derives the AES key from the session password and the per-blob salt.
 * A fresh salt per seal() means two wallets that somehow share a password
 * still never share a key stream.
 */
SecureBytes deriveKey(const SecureBytes &password, const unsigned char *salt)
{
    SecureBytes key(kKeyBytes);
    const int ok = PKCS5_PBKDF2_HMAC(password.chars(),
                                     static_cast<int>(password.size()),
                                     salt,
                                     kSaltBytes,
                                     kPbkdf2Iterations,
                                     EVP_sha256(),
                                     kKeyBytes,
                                     key.data());
    if (ok != 1)
        throw CryptoError(QStringLiteral("PBKDF2 failed: %1").arg(lastOpenSslError()));
    return key;
}

} // namespace

SecureBytes randomBytes(std::size_t count)
{
    SecureBytes bytes(count);
    if (count > 0 && RAND_bytes(bytes.data(), static_cast<int>(count)) != 1)
        throw CryptoError(QStringLiteral("RAND_bytes failed: %1").arg(lastOpenSslError()));
    return bytes;
}

SecureBytes generateSessionPassword()
{
    SecureBytes entropy = randomBytes(kKeyBytes);

    QByteArray raw = QByteArray::fromRawData(entropy.chars(), static_cast<qsizetype>(entropy.size()));
    QByteArray encoded = raw.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);

    SecureBytes password = SecureBytes::adopt(encoded);
    return password;
}

QByteArray seal(const SecureBytes &plaintext, const SecureBytes &password)
{
    const SecureBytes salt = randomBytes(kSaltBytes);
    const SecureBytes iv = randomBytes(kIvBytes);
    const SecureBytes key = deriveKey(password, salt.data());

    QByteArray header;
    header.reserve(kHeaderBytes);
    header.append(kMagic, sizeof(kMagic));
    header.append(static_cast<char>(kVersion));
    header.append(salt.chars(), static_cast<qsizetype>(salt.size()));
    header.append(iv.chars(), static_cast<qsizetype>(iv.size()));

    CipherCtx ctx(EVP_CIPHER_CTX_new(), &EVP_CIPHER_CTX_free);
    if (!ctx)
        throw CryptoError(QStringLiteral("EVP_CIPHER_CTX_new failed"));

    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1
        || EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, kIvBytes, nullptr) != 1
        || EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), iv.data()) != 1) {
        throw CryptoError(QStringLiteral("AES-256-GCM init failed: %1").arg(lastOpenSslError()));
    }

    // Bind the header to the ciphertext so salt/IV cannot be swapped.
    int scratch = 0;
    if (EVP_EncryptUpdate(ctx.get(),
                          nullptr,
                          &scratch,
                          reinterpret_cast<const unsigned char *>(header.constData()),
                          static_cast<int>(header.size())) != 1) {
        throw CryptoError(QStringLiteral("AAD update failed: %1").arg(lastOpenSslError()));
    }

    QByteArray ciphertext(static_cast<qsizetype>(plaintext.size()), Qt::Uninitialized);
    int written = 0;
    if (!plaintext.isEmpty()
        && EVP_EncryptUpdate(ctx.get(),
                             reinterpret_cast<unsigned char *>(ciphertext.data()),
                             &written,
                             plaintext.data(),
                             static_cast<int>(plaintext.size())) != 1) {
        wipe(ciphertext);
        throw CryptoError(QStringLiteral("encrypt failed: %1").arg(lastOpenSslError()));
    }

    int finalWritten = 0;
    // GCM is a stream mode: EncryptFinal emits no bytes, but it must run for
    // the tag to be computed.
    if (EVP_EncryptFinal_ex(ctx.get(),
                            reinterpret_cast<unsigned char *>(ciphertext.data()) + written,
                            &finalWritten) != 1) {
        wipe(ciphertext);
        throw CryptoError(QStringLiteral("encrypt finalise failed: %1").arg(lastOpenSslError()));
    }
    ciphertext.resize(static_cast<qsizetype>(written + finalWritten));

    unsigned char tag[kTagBytes] = {};
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, kTagBytes, tag) != 1) {
        wipe(ciphertext);
        throw CryptoError(QStringLiteral("tag extraction failed: %1").arg(lastOpenSslError()));
    }

    QByteArray blob;
    blob.reserve(header.size() + kTagBytes + ciphertext.size());
    blob.append(header);
    blob.append(reinterpret_cast<const char *>(tag), kTagBytes);
    blob.append(ciphertext);

    wipe(ciphertext);
    return blob;
}

std::optional<SecureBytes> open(const QByteArray &blob, const SecureBytes &password)
{
    if (blob.size() < kHeaderBytes + kTagBytes)
        return std::nullopt;
    if (std::memcmp(blob.constData(), kMagic, sizeof(kMagic)) != 0)
        return std::nullopt;
    if (static_cast<quint8>(blob.at(sizeof(kMagic))) != kVersion)
        return std::nullopt;

    const auto *bytes = reinterpret_cast<const unsigned char *>(blob.constData());
    const unsigned char *salt = bytes + sizeof(kMagic) + 1;
    const unsigned char *iv = salt + kSaltBytes;
    const unsigned char *tag = bytes + kHeaderBytes;
    const unsigned char *ciphertext = tag + kTagBytes;
    const int ciphertextSize = static_cast<int>(blob.size()) - kHeaderBytes - kTagBytes;

    SecureBytes key;
    try {
        key = deriveKey(password, salt);
    } catch (const CryptoError &) {
        return std::nullopt;
    }

    CipherCtx ctx(EVP_CIPHER_CTX_new(), &EVP_CIPHER_CTX_free);
    if (!ctx)
        return std::nullopt;

    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1
        || EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, kIvBytes, nullptr) != 1
        || EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), iv) != 1) {
        ERR_clear_error();
        return std::nullopt;
    }

    int scratch = 0;
    if (EVP_DecryptUpdate(ctx.get(), nullptr, &scratch, bytes, kHeaderBytes) != 1) {
        ERR_clear_error();
        return std::nullopt;
    }

    SecureBytes plaintext(static_cast<std::size_t>(ciphertextSize));
    int written = 0;
    if (ciphertextSize > 0
        && EVP_DecryptUpdate(ctx.get(), plaintext.data(), &written, ciphertext, ciphertextSize) != 1) {
        ERR_clear_error();
        return std::nullopt;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx.get(),
                            EVP_CTRL_GCM_SET_TAG,
                            kTagBytes,
                            const_cast<unsigned char *>(tag)) != 1) {
        ERR_clear_error();
        return std::nullopt;
    }

    int finalWritten = 0;
    // This is the authentication check. A wrong password lands here.
    if (EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + written, &finalWritten) != 1) {
        ERR_clear_error();
        return std::nullopt;
    }

    const auto produced = static_cast<std::size_t>(written + finalWritten);
    if (produced == plaintext.size())
        return plaintext;

    // Shrink to the exact plaintext length without leaving a longer copy behind.
    SecureBytes exact(plaintext.data(), produced);
    return exact;
}

} // namespace SessionCrypto
