// AVXTO Wallet Manager
// Copyright (c) 2026, @REKTBuildr
//
// SPDX-License-Identifier: BSD-3-Clause
// See the LICENSE file in the project root for the full license text.

#pragma once

#include "SecureBytes.h"

#include <QDateTime>
#include <QString>

#include <memory>
#include <optional>

/*!
 * \brief One wallet that is currently unlocked in the application.
 *
 * The invariant this class exists to hold: after construction the mnemonic
 * exists in this process **only** as an AES-256-GCM blob. Recovering it needs
 * the session password, which is generated fresh for every open and which the
 * user is shown so they can drive the RPC endpoint.
 *
 * First and last word are extracted once at construction and kept in the
 * clear on purpose — the UI has to display them, and two words out of
 * twenty-four are not a meaningful reduction in search space (2^242 remains).
 */
class WalletSession
{
public:
    /*!
     * Seals \a mnemonic under a newly generated session password.
     * \throws SessionCrypto::CryptoError on RNG/cipher failure.
     */
    WalletSession(QString fileName, QString filePath, const SecureBytes &mnemonic, int wordCount);

    WalletSession(const WalletSession &) = delete;
    WalletSession &operator=(const WalletSession &) = delete;

    [[nodiscard]] const QString &fileName() const noexcept { return m_fileName; }
    [[nodiscard]] const QString &filePath() const noexcept { return m_filePath; }
    [[nodiscard]] const QString &firstWord() const noexcept { return m_firstWord; }
    [[nodiscard]] const QString &lastWord() const noexcept { return m_lastWord; }
    [[nodiscard]] int wordCount() const noexcept { return m_wordCount; }
    [[nodiscard]] const QDateTime &openedAt() const noexcept { return m_openedAt; }

    //! The session password, for display in the UI and for RPC callers.
    [[nodiscard]] const SecureBytes &sessionPassword() const noexcept { return m_sessionPassword; }

    /*!
     * Returns the mnemonic if \a password is the session password for this
     * wallet, nullopt otherwise. Verification is the AES-GCM tag check itself,
     * so there is no separate comparison to get wrong.
     */
    [[nodiscard]] std::optional<SecureBytes> revealMnemonic(const SecureBytes &password) const;

    //! Cheap pre-check used by the registry to find the matching session.
    [[nodiscard]] bool passwordMatches(const SecureBytes &password) const;

private:
    QString m_fileName;
    QString m_filePath;
    QString m_firstWord;
    QString m_lastWord;
    int m_wordCount = 0;
    QDateTime m_openedAt;

    SecureBytes m_sessionPassword;
    QByteArray m_sealedMnemonic; //!< AES-256-GCM blob; ciphertext only
};

using WalletSessionPtr = std::shared_ptr<WalletSession>;
