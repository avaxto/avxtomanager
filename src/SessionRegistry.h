// AVXTO Wallet Manager
// Copyright (c) 2026, @REKTBuildr
//
// SPDX-License-Identifier: BSD-3-Clause
// See the LICENSE file in the project root for the full license text.

#pragma once

#include "WalletSession.h"

#include <QMutex>
#include <QObject>
#include <QString>

#include <optional>

/*!
 * \brief Thread-safe collection of the wallets that are currently unlocked.
 *
 * The GUI thread inserts and removes sessions; the RPC server reads them.
 * Both go through the same mutex, and lookups hand back a shared_ptr so a
 * request in flight cannot be invalidated by the user closing the wallet
 * mid-call.
 */
class SessionRegistry : public QObject
{
    Q_OBJECT

public:
    explicit SessionRegistry(QObject *parent = nullptr);

    //! Replaces any existing session for the same file. Returns the new one.
    WalletSessionPtr insert(WalletSessionPtr session);

    //! Removes the session for \a filePath. Returns true if one was present.
    bool remove(const QString &filePath);

    void clear();

    [[nodiscard]] WalletSessionPtr find(const QString &filePath) const;

    /*!
     * Finds the unlocked wallet whose session password is \a password.
     *
     * Every candidate is compared even after a hit, so the time taken does
     * not reveal the position of the matching wallet in the table.
     */
    [[nodiscard]] WalletSessionPtr findByPassword(const SecureBytes &password) const;

    [[nodiscard]] QList<WalletSessionPtr> all() const;
    [[nodiscard]] int count() const;

signals:
    //! Emitted after any change, so the UI can refresh lock indicators.
    void changed();

private:
    mutable QMutex m_mutex;
    QList<WalletSessionPtr> m_sessions;
};
