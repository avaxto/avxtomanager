// AVXTO Wallet Manager
// Copyright (c) 2026, @REKTBuildr
//
// SPDX-License-Identifier: BSD-3-Clause
// See the LICENSE file in the project root for the full license text.

#include "RpcServer.h"

#include "SecureBytes.h"
#include "SessionRegistry.h"
#include "WalletSession.h"

#include <QDateTime>
#include <QJsonDocument>
#include <QJsonArray>
#include <QJsonObject>
#include <QJsonValue>
#include <QTcpSocket>
#include <QTimer>

namespace {

//! A JSON-RPC request for one mnemonic is tiny; anything larger is not ours.
constexpr qint64 kMaxHeaderBytes = 8 * 1024;
constexpr qint64 kMaxBodyBytes = 64 * 1024;
//! Drop a client that opens a socket and then says nothing.
constexpr int kIdleTimeoutMs = 15'000;

//! Failed-auth throttle: after this many failures in the window, stop answering.
constexpr int kMaxAuthFailures = 10;
constexpr qint64 kThrottleWindowMs = 60'000;

constexpr int kErrorParse = -32700;
constexpr int kErrorInvalidRequest = -32600;
constexpr int kErrorMethodNotFound = -32601;
constexpr int kErrorInvalidParams = -32602;
constexpr int kErrorDenied = -32001;

QByteArray encodeJson(const QJsonObject &object)
{
    return QJsonDocument(object).toJson(QJsonDocument::Compact);
}

QJsonObject errorEnvelope(const QJsonValue &id, int code, const QString &message)
{
    QJsonObject error;
    error.insert(QStringLiteral("code"), code);
    error.insert(QStringLiteral("message"), message);

    QJsonObject envelope;
    envelope.insert(QStringLiteral("jsonrpc"), QStringLiteral("2.0"));
    envelope.insert(QStringLiteral("id"), id.isUndefined() ? QJsonValue(QJsonValue::Null) : id);
    envelope.insert(QStringLiteral("error"), error);
    return envelope;
}

} // namespace

RpcServer::RpcServer(SessionRegistry *registry, QObject *parent)
    : QObject(parent)
    , m_server(new QTcpServer(this))
    , m_registry(registry)
{
    connect(m_server, &QTcpServer::newConnection, this, &RpcServer::onNewConnection);
}

RpcServer::~RpcServer()
{
    stop();
}

bool RpcServer::start(quint16 preferredPort)
{
    if (m_server->isListening())
        return true;

    // Loopback only. Binding QHostAddress::Any here would put a plaintext
    // mnemonic endpoint on every interface of the machine.
    const bool ok = m_server->listen(QHostAddress::LocalHost, preferredPort);
    if (ok)
        emit listeningChanged();
    return ok;
}

void RpcServer::stop()
{
    if (!m_server->isListening() && m_connections.isEmpty())
        return;

    const auto sockets = m_connections.keys();
    for (QTcpSocket *socket : sockets) {
        socket->abort();
        socket->deleteLater();
    }
    m_connections.clear();
    m_server->close();
    emit listeningChanged();
}

bool RpcServer::isListening() const
{
    return m_server->isListening();
}

quint16 RpcServer::port() const
{
    return m_server->isListening() ? m_server->serverPort() : quint16{0};
}

QString RpcServer::endpoint() const
{
    return isListening() ? QStringLiteral("http://127.0.0.1:%1/").arg(port()) : QString();
}

void RpcServer::onNewConnection()
{
    while (QTcpSocket *socket = m_server->nextPendingConnection()) {
        // The listening socket is already loopback-bound; this is belt and
        // braces against a misconfiguration or a future change to start().
        if (!socket->peerAddress().isLoopback()) {
            socket->abort();
            socket->deleteLater();
            continue;
        }

        m_connections.insert(socket, Connection{});

        connect(socket, &QTcpSocket::readyRead, this, [this, socket] { onReadyRead(socket); });
        connect(socket, &QTcpSocket::disconnected, this, [this, socket] {
            auto it = m_connections.find(socket);
            if (it != m_connections.end()) {
                wipe(it->buffer);
                m_connections.erase(it);
            }
            socket->deleteLater();
        });

        QTimer::singleShot(kIdleTimeoutMs, socket, [socket] {
            if (socket->state() != QAbstractSocket::UnconnectedState)
                socket->disconnectFromHost();
        });
    }
}

void RpcServer::onReadyRead(QTcpSocket *socket)
{
    auto it = m_connections.find(socket);
    if (it == m_connections.end())
        return;
    Connection &connection = *it;

    connection.buffer.append(socket->readAll());

    if (!connection.headersParsed) {
        const qint64 separator = connection.buffer.indexOf("\r\n\r\n");
        if (separator < 0) {
            if (connection.buffer.size() > kMaxHeaderBytes) {
                // Headers aren't fully received, so Origin isn't known yet;
                // "*" is a harmless fallback since a legitimate CORS
                // preflight is nowhere near this size limit.
                sendResponse(socket, 431, "Request Header Fields Too Large", {}, {});
                socket->disconnectFromHost();
            }
            return; // keep waiting for the rest of the headers
        }

        const QByteArray head = connection.buffer.left(separator);
        const QList<QByteArray> lines = head.split('\n');
        if (lines.isEmpty()) {
            sendResponse(socket, 400, "Bad Request", {}, {});
            socket->disconnectFromHost();
            return;
        }

        const QList<QByteArray> requestLine = lines.first().trimmed().simplified().split(' ');
        if (requestLine.size() < 2) {
            sendResponse(socket, 400, "Bad Request", {}, {});
            socket->disconnectFromHost();
            return;
        }
        connection.method = requestLine.at(0).toUpper();
        connection.target = requestLine.at(1);

        for (qsizetype i = 1; i < lines.size(); ++i) {
            const QByteArray line = lines.at(i).trimmed();
            const qsizetype colon = line.indexOf(':');
            if (colon < 0)
                continue;
            const QByteArray name = line.left(colon).trimmed().toLower();
            if (name == "content-length") {
                bool ok = false;
                connection.contentLength = line.mid(colon + 1).trimmed().toLongLong(&ok);
                if (!ok || connection.contentLength < 0)
                    connection.contentLength = 0;
            } else if (name == "origin") {
                connection.origin = line.mid(colon + 1).trimmed();
            }
        }

        if (connection.contentLength > kMaxBodyBytes) {
            sendResponse(socket, 413, "Payload Too Large", {}, connection.origin);
            socket->disconnectFromHost();
            return;
        }

        connection.headerEnd = separator + 4;
        connection.headersParsed = true;
    }

    const qint64 available = connection.buffer.size() - connection.headerEnd;
    if (available < connection.contentLength)
        return; // body still arriving

    handleRequest(socket, connection);
}

void RpcServer::handleRequest(QTcpSocket *socket, Connection &connection)
{
    const QString peer = QStringLiteral("127.0.0.1:%1").arg(socket->peerPort());
    auto log = [this, peer](const QString &what) {
        emit requestLogged(QStringLiteral("[%1] %2  %3")
                               .arg(QDateTime::currentDateTime().toString(Qt::ISODate), peer, what));
    };

    const QByteArray origin = connection.origin;

    QByteArray body = connection.buffer.mid(connection.headerEnd, connection.contentLength);
    // The connection is single-shot; scrub the accumulated bytes now.
    wipe(connection.buffer);
    connection.headersParsed = false;

    auto finish = [&](int status, const QByteArray &reason, QJsonObject envelope) {
        QByteArray encoded = encodeJson(envelope);
        envelope = QJsonObject{};
        sendResponse(socket, status, reason, encoded, origin);
        wipe(encoded);
        wipe(body);
        socket->disconnectFromHost();
    };

    if (connection.method == "OPTIONS") {
        // CORS preflight. The browser is only checking whether it is allowed
        // to send the real request; it carries no JSON-RPC payload, so this
        // must not touch the JSON parser, the session registry or the
        // failed-auth throttle — sendResponse() already puts the
        // Access-Control-Allow-* headers on every reply, preflight included.
        wipe(body);
        sendResponse(socket, 204, "No Content", {}, origin);
        socket->disconnectFromHost();
        return;
    }

    if (connection.method != "POST") {
        log(QStringLiteral("%1 -> 405").arg(QString::fromLatin1(connection.method)));
        finish(405,
               "Method Not Allowed",
               errorEnvelope(QJsonValue(QJsonValue::Null),
                             kErrorInvalidRequest,
                             QStringLiteral("Only HTTP POST is accepted.")));
        return;
    }

    if (isThrottled()) {
        log(QStringLiteral("read -> 429 (throttled)"));
        finish(429,
               "Too Many Requests",
               errorEnvelope(QJsonValue(QJsonValue::Null),
                             kErrorDenied,
                             QStringLiteral("Too many failed attempts. Try again shortly.")));
        return;
    }

    QJsonParseError parseError{};
    const QJsonDocument document = QJsonDocument::fromJson(body, &parseError);
    if (parseError.error != QJsonParseError::NoError || !document.isObject()) {
        log(QStringLiteral("-> 400 (malformed JSON)"));
        finish(400,
               "Bad Request",
               errorEnvelope(QJsonValue(QJsonValue::Null),
                             kErrorParse,
                             QStringLiteral("Request body is not a JSON object.")));
        return;
    }

    const QJsonObject request = document.object();
    const QJsonValue id = request.value(QStringLiteral("id"));
    const QString method = request.value(QStringLiteral("method")).toString();

    if (method != QLatin1String("read")) {
        log(QStringLiteral("%1 -> 200 (unknown method)").arg(method.isEmpty() ? QStringLiteral("(none)") : method));
        finish(200,
               "OK",
               errorEnvelope(id,
                             kErrorMethodNotFound,
                             QStringLiteral("Unknown method. This server implements \"read\".")));
        return;
    }

    const QJsonValue paramsValue = request.value(QStringLiteral("params"));
    QString passwordText;
    QString requestedWallet;
    if (paramsValue.isObject()) {
        const QJsonObject params = paramsValue.toObject();
        passwordText = params.value(QStringLiteral("password")).toString();
        requestedWallet = params.value(QStringLiteral("wallet")).toString();
    } else if (paramsValue.isArray()) {
        // Positional form: ["<password>"] or ["<password>", "<wallet>"].
        const QJsonArray params = paramsValue.toArray();
        if (!params.isEmpty())
            passwordText = params.at(0).toString();
        if (params.size() > 1)
            requestedWallet = params.at(1).toString();
    }

    if (passwordText.isEmpty()) {
        recordAuthFailure();
        log(QStringLiteral("read -> 403 (no password)"));
        finish(403,
               "Forbidden",
               errorEnvelope(id, kErrorInvalidParams, QStringLiteral("denied")));
        return;
    }

    SecureBytes password = SecureBytes::fromUtf8(passwordText);
    wipe(passwordText);

    const WalletSessionPtr session = m_registry->findByPassword(password);

    // A wallet name may be supplied, but it narrows rather than authorises:
    // the password alone decides which wallet the caller may read.
    if (!session || (!requestedWallet.isEmpty() && session->fileName() != requestedWallet)) {
        recordAuthFailure();
        log(QStringLiteral("read -> 403 denied"));
        finish(403, "Forbidden", errorEnvelope(id, kErrorDenied, QStringLiteral("denied")));
        return;
    }

    std::optional<SecureBytes> mnemonic = session->revealMnemonic(password);
    if (!mnemonic) {
        // Should be unreachable: the password already selected this session.
        recordAuthFailure();
        log(QStringLiteral("read -> 403 denied (decrypt failed)"));
        finish(403, "Forbidden", errorEnvelope(id, kErrorDenied, QStringLiteral("denied")));
        return;
    }

    m_authFailures = 0;

    QString mnemonicText = mnemonic->toQString();
    mnemonic.reset();

    QJsonObject result;
    result.insert(QStringLiteral("wallet"), session->fileName());
    result.insert(QStringLiteral("mnemonic"), mnemonicText);
    result.insert(QStringLiteral("wordCount"), session->wordCount());
    result.insert(QStringLiteral("firstWord"), session->firstWord());
    result.insert(QStringLiteral("lastWord"), session->lastWord());
    wipe(mnemonicText);

    QJsonObject envelope;
    envelope.insert(QStringLiteral("jsonrpc"), QStringLiteral("2.0"));
    envelope.insert(QStringLiteral("id"), id.isUndefined() ? QJsonValue(QJsonValue::Null) : id);
    envelope.insert(QStringLiteral("result"), result);
    result = QJsonObject{};

    log(QStringLiteral("read %1 -> 200 OK").arg(session->fileName()));
    finish(200, "OK", std::move(envelope));
}

void RpcServer::sendResponse(QTcpSocket *socket,
                             int statusCode,
                             const QByteArray &reasonPhrase,
                             QByteArray body,
                             const QByteArray &origin) const
{
    if (!socket || socket->state() != QAbstractSocket::ConnectedState) {
        wipe(body);
        return;
    }

    QByteArray response;
    response.reserve(body.size() + 384);
    response.append("HTTP/1.1 ");
    response.append(QByteArray::number(statusCode));
    response.append(' ');
    response.append(reasonPhrase);
    response.append("\r\n");
    response.append("Content-Type: application/json\r\n");
    response.append("Content-Length: ");
    response.append(QByteArray::number(body.size()));
    response.append("\r\n");
    response.append("Cache-Control: no-store\r\n");
    response.append("Connection: close\r\n");
    // The response can carry a mnemonic; keep it out of any intermediary.
    response.append("X-Content-Type-Options: nosniff\r\n");
    // CORS: the session password is this endpoint's real credential, not
    // the caller's origin — a page that already holds a valid password is
    // meant to be able to read the response back, whatever site it was
    // served from. Reflecting the request's own Origin (falling back to
    // "*" for a non-browser caller, e.g. curl, that sends none) works for
    // any frontend without hardcoding one, and must be present on every
    // response, the OPTIONS preflight included, or the browser refuses to
    // hand the page the result even when the request itself succeeded.
    response.append("Access-Control-Allow-Origin: ");
    response.append(origin.isEmpty() ? QByteArray("*") : origin);
    response.append("\r\n");
    response.append("Access-Control-Allow-Methods: POST, OPTIONS\r\n");
    response.append("Access-Control-Allow-Headers: Content-Type\r\n");
    response.append("\r\n");
    response.append(body);

    socket->write(response);
    socket->flush();

    wipe(response);
    wipe(body);
}

bool RpcServer::isThrottled()
{
    const qint64 now = QDateTime::currentMSecsSinceEpoch();
    if (now - m_throttleWindowStartMs > kThrottleWindowMs) {
        m_throttleWindowStartMs = now;
        m_authFailures = 0;
        return false;
    }
    return m_authFailures >= kMaxAuthFailures;
}

void RpcServer::recordAuthFailure()
{
    const qint64 now = QDateTime::currentMSecsSinceEpoch();
    if (now - m_throttleWindowStartMs > kThrottleWindowMs) {
        m_throttleWindowStartMs = now;
        m_authFailures = 0;
    }
    ++m_authFailures;
}
