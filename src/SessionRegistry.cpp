// AVXTO Wallet Manager
// Copyright (c) 2026, @REKTBuildr
//
// SPDX-License-Identifier: BSD-3-Clause
// See the LICENSE file in the project root for the full license text.

#include "SessionRegistry.h"

#include <QMutexLocker>

SessionRegistry::SessionRegistry(QObject *parent)
    : QObject(parent)
{
}

WalletSessionPtr SessionRegistry::insert(WalletSessionPtr session)
{
    if (!session)
        return session;
    {
        QMutexLocker locker(&m_mutex);
        // Re-opening a wallet supersedes the previous session, which also
        // means the previously displayed password stops working.
        for (auto it = m_sessions.begin(); it != m_sessions.end(); ++it) {
            if ((*it)->filePath() == session->filePath()) {
                m_sessions.erase(it);
                break;
            }
        }
        m_sessions.append(session);
    }
    emit changed();
    return session;
}

bool SessionRegistry::remove(const QString &filePath)
{
    bool removed = false;
    {
        QMutexLocker locker(&m_mutex);
        for (auto it = m_sessions.begin(); it != m_sessions.end(); ++it) {
            if ((*it)->filePath() == filePath) {
                m_sessions.erase(it);
                removed = true;
                break;
            }
        }
    }
    if (removed)
        emit changed();
    return removed;
}

void SessionRegistry::clear()
{
    bool hadAny = false;
    {
        QMutexLocker locker(&m_mutex);
        hadAny = !m_sessions.isEmpty();
        m_sessions.clear();
    }
    if (hadAny)
        emit changed();
}

WalletSessionPtr SessionRegistry::find(const QString &filePath) const
{
    QMutexLocker locker(&m_mutex);
    for (const auto &session : m_sessions) {
        if (session->filePath() == filePath)
            return session;
    }
    return {};
}

WalletSessionPtr SessionRegistry::findByPassword(const SecureBytes &password) const
{
    QMutexLocker locker(&m_mutex);
    WalletSessionPtr match;
    for (const auto &session : m_sessions) {
        // No early exit: the loop runs over every session regardless.
        if (session->passwordMatches(password) && !match)
            match = session;
    }
    return match;
}

QList<WalletSessionPtr> SessionRegistry::all() const
{
    QMutexLocker locker(&m_mutex);
    return m_sessions;
}

int SessionRegistry::count() const
{
    QMutexLocker locker(&m_mutex);
    return static_cast<int>(m_sessions.size());
}
