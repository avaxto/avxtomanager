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
 *
 * CORS is allowed for an explicit set of origins — the production wallet
 * frontend at https://wallet.avax.to, and any localhost/127.0.0.1 dev server
 * regardless of port, for local development — plus "*" for a non-browser
 * caller that sends no Origin header at all. Anything else gets a response
 * with no Access-Control-Allow-Origin, so the browser refuses to expose it
 * to the page's script even though the request still ran (CORS is a
 * browser-side read restriction, not a server-side access control: the
 * session password stays the real credential regardless of origin). OPTIONS
 * preflights are answered the same way, without touching the session
 * registry or the auth-failure throttle. See allowedCorsOrigin() in
 * RpcServer.cpp for the allowlist itself.
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
        QByteArray origin;  //!< the request's raw Origin header; empty if none sent
    };

    void onNewConnection();
    void onReadyRead(QTcpSocket *socket);
    void handleRequest(QTcpSocket *socket, Connection &connection);

    /*!
     * \a corsOrigin is the value to send as Access-Control-Allow-Origin —
     * already decided by allowedCorsOrigin() in RpcServer.cpp, not the raw
     * Origin header — or an empty QByteArray to omit the header entirely.
     * Sent on every response, the OPTIONS preflight included.
     */
    void sendResponse(QTcpSocket *socket,
                      int statusCode,
                      const QByteArray &reasonPhrase,
                      QByteArray body,
                      const QByteArray &corsOrigin) const;

    //! True when the caller has tripped the failed-authentication throttle.
    [[nodiscard]] bool isThrottled();
    void recordAuthFailure();

    QTcpServer *m_server;
    SessionRegistry *m_registry;
    QHash<QTcpSocket *, Connection> m_connections;

    int m_authFailures = 0;
    qint64 m_throttleWindowStartMs = 0;
};
