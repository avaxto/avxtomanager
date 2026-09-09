// AVXTO Wallet Manager
// Copyright (c) 2026, @REKTBuildr
//
// SPDX-License-Identifier: BSD-3-Clause
// See the LICENSE file in the project root for the full license text.

#pragma once

#include <QHash>
#include <QHostAddress>
#include <QObject>
#include <QTcpServer>

class QTcpSocket;
class SessionRegistry;

/*!
 * \brief Minimal HTTP/1.1 front end exposing a JSON-RPC 2.0 "read" method.
 *
 * Bound to 127.0.0.1 on an ephemeral port chosen by the OS. The session
 * password of an unlocked wallet is the only credential; a request that does
 * not present one gets 403.
 *
 * Request:
 * \code
 * POST / HTTP/1.1
 * Content-Type: application/json
 *
 * {"jsonrpc":"2.0","id":1,"method":"read","params":{"password":"<session>"}}
 * \endcode
 *
 * Response:
 * \code
 * {"jsonrpc":"2.0","id":1,
 *  "result":{"wallet":"main.bin","mnemonic":"abandon ... art","wordCount":24}}
 * \endcode
 *
 * This is plaintext HTTP on the loopback interface. Any process running as
 * this user can connect to it; the password is what keeps it honest, not the
 * transport. See notes/initiallog.txt for the threat model.
 */
class RpcServer : public QObject
{
    Q_OBJECT

public:
    explicit RpcServer(SessionRegistry *registry, QObject *parent = nullptr);
    ~RpcServer() override;

    //! Binds to 127.0.0.1 on an OS-assigned free port. \a preferredPort 0 = any.
    bool start(quint16 preferredPort = 0);
    void stop();

    [[nodiscard]] bool isListening() const;
    [[nodiscard]] quint16 port() const;
    [[nodiscard]] QString endpoint() const;

signals:
    void listeningChanged();
    //! One line per request, for the activity log in the status area.
    void requestLogged(const QString &line);

private:
    struct Connection
    {
        QByteArray buffer;
        bool headersParsed = false;
        qint64 contentLength = 0;
        qint64 headerEnd = 0;
        QByteArray method;
        QByteArray target;
    };

    void onNewConnection();
    void onReadyRead(QTcpSocket *socket);
    void handleRequest(QTcpSocket *socket, Connection &connection);

    void sendResponse(QTcpSocket *socket,
                      int statusCode,
                      const QByteArray &reasonPhrase,
                      QByteArray body) const;

    //! True when the caller has tripped the failed-authentication throttle.
    [[nodiscard]] bool isThrottled();
    void recordAuthFailure();

    QTcpServer *m_server;
    SessionRegistry *m_registry;
    QHash<QTcpSocket *, Connection> m_connections;

    int m_authFailures = 0;
    qint64 m_throttleWindowStartMs = 0;
};
