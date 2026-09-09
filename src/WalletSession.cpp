// AVXTO Wallet Manager
// Copyright (c) 2026, @REKTBuildr
//
// SPDX-License-Identifier: BSD-3-Clause
// See the LICENSE file in the project root for the full license text.

#include "WalletSession.h"

#include "Bip39.h"
#include "SessionCrypto.h"

WalletSession::WalletSession(QString fileName,
                             QString filePath,
                             const SecureBytes &mnemonic,
                             int wordCount)
    : m_fileName(std::move(fileName))
    , m_filePath(std::move(filePath))
    , m_wordCount(wordCount)
    , m_openedAt(QDateTime::currentDateTime())
    , m_sessionPassword(SessionCrypto::generateSessionPassword())
{
    QString text = mnemonic.toQString();
    const QStringList words = Bip39::splitWords(text);
    wipe(text);

    if (!words.isEmpty()) {
        m_firstWord = words.first();
        m_lastWord = words.last();
        if (m_wordCount == 0)
            m_wordCount = static_cast<int>(words.size());
    }

    m_sealedMnemonic = SessionCrypto::seal(mnemonic, m_sessionPassword);
}

std::optional<SecureBytes> WalletSession::revealMnemonic(const SecureBytes &password) const
{
    return SessionCrypto::open(m_sealedMnemonic, password);
}

bool WalletSession::passwordMatches(const SecureBytes &password) const
{
    return m_sessionPassword.constantTimeEquals(password);
}
