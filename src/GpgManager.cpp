// AVXTO Wallet Manager
// Copyright (c) 2026, @REKTBuildr
//
// SPDX-License-Identifier: BSD-3-Clause
// See the LICENSE file in the project root for the full license text.

#include "GpgManager.h"

#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QPointer>
#include <QProcess>
#include <QSaveFile>
#include <QSet>
#include <QStandardPaths>

namespace {

//! gpg can sit in pinentry for a long time; encryption never prompts.
constexpr int kEncryptTimeoutMs = 30'000;
constexpr int kListTimeoutMs = 20'000;

//! Refuse absurdly large wallet files rather than reading them into memory.
constexpr qint64 kMaxWalletFileBytes = 1 << 20; // 1 MiB

QString colonField(const QStringList &fields, int index)
{
    return index < fields.size() ? fields.at(index) : QString();
}

//! Validity codes that mean the key must not be offered as a recipient.
bool validityIsUsable(const QString &validity)
{
    if (validity.isEmpty())
        return true;
    const QChar code = validity.at(0);
    return code != QLatin1Char('r')   // revoked
        && code != QLatin1Char('e')   // expired
        && code != QLatin1Char('d')   // disabled
        && code != QLatin1Char('i');  // invalid
}

/*!
 * Recognises the specific way pinentry-curses (or plain pinentry-tty) fails
 * when it is asked to prompt for a passphrase but has no controlling
 * terminal to draw into — exactly the situation gpg-agent is in when a GUI
 * application like this one spawns gpg as a subprocess. QProcess gives the
 * child pipes, not a real TTY, so a text-mode pinentry can never work here
 * no matter how it is invoked; only a graphical one can. This is a one-time
 * system configuration issue, not something this application can fix from
 * inside its own sandbox, so the best it can do is name the actual cause and
 * the two-line fix instead of leaving the user with a bare gpg exit code.
 *
 * "public key decryption failed: <errno text>" is gpg's own wrapper for any
 * failure at the gpg-agent/pinentry round-trip stage, before a passphrase is
 * even checked — the trailing OS error varies by platform, gpg version and
 * exactly how the terminal is missing ("Screen or window too small" and "No
 * such file or directory" have both been observed for this identical root
 * cause), so this keys off that stable prefix rather than the errno text.
 */
QString pinentryTtyHint(const QString &stderrText)
{
    if (!stderrText.contains(QLatin1String("public key decryption failed"))
        && !stderrText.contains(QLatin1String("Screen or window too small"))
        && !stderrText.contains(QLatin1String("Inappropriate ioctl for device"))) {
        return {};
    }

#if defined(Q_OS_MACOS)
    return QStringLiteral(
        "\n\nThis is gpg-agent trying to use a text-mode pinentry "
        "(pinentry-curses), which needs a terminal window — something a "
        "GUI application like this one cannot give it. Install a graphical "
        "pinentry and point gpg-agent at it, then try again:\n\n"
        "    brew install pinentry-mac\n"
        "    echo \"pinentry-program $(brew --prefix)/bin/pinentry-mac\" >> ~/.gnupg/gpg-agent.conf\n"
        "    gpgconf --kill gpg-agent");
#else
    return QStringLiteral(
        "\n\nThis is gpg-agent trying to use a text-mode pinentry "
        "(pinentry-curses), which needs a terminal window — something a "
        "GUI application like this one cannot give it. Install a graphical "
        "pinentry and point gpg-agent at it, then try again, e.g.:\n\n"
        "    sudo apt install pinentry-gnome3   # or pinentry-qt / pinentry-gtk2\n"
        "    echo \"pinentry-program /usr/bin/pinentry-gnome3\" >> ~/.gnupg/gpg-agent.conf\n"
        "    gpgconf --kill gpg-agent");
#endif
}

} // namespace

QString GpgKey::displayName() const
{
    QString name = userId.isEmpty() ? QStringLiteral("(no user id)") : userId;
    return QStringLiteral("%1  —  %2 %3").arg(name, algorithm, keyId);
}

QString GpgRecipient::displayText() const
{
    if (!ok)
        return QStringLiteral("unknown (%1)").arg(error);
    if (!userId.isEmpty())
        return QStringLiteral("%1  —  %2").arg(userId, keyId);
    return QStringLiteral("key %1 (not in local keyring)").arg(keyId);
}

// ---------------------------------------------------------------------------
// GpgDecryptOperation
// ---------------------------------------------------------------------------

GpgDecryptOperation::GpgDecryptOperation(QProcess *process, QObject *parent)
    : QObject(parent)
    , m_process(process)
{
}

GpgDecryptOperation::~GpgDecryptOperation() = default;

void GpgDecryptOperation::cancel()
{
    if (m_cancelled || !m_process)
        return;
    m_cancelled = true;
    // terminate() lets gpg-agent tear the pinentry dialog down cleanly.
    m_process->terminate();
    if (!m_process->waitForFinished(2000))
        m_process->kill();
}

// ---------------------------------------------------------------------------
// GpgManager
// ---------------------------------------------------------------------------

GpgManager::GpgManager(QObject *parent)
    : QObject(parent)
    , m_gpgExecutable(findGpgExecutable())
{
}

GpgManager::~GpgManager() = default;

void GpgManager::setGpgExecutable(const QString &path)
{
    m_gpgExecutable = path;
}

QString GpgManager::findGpgExecutable()
{
    // QStandardPaths::findExecutable searches PATH, which under a macOS .app
    // bundle launched from Finder is the bare login PATH — hence the explicit
    // fallbacks for the common package managers.
    for (const auto &name : {QStringLiteral("gpg"), QStringLiteral("gpg2")}) {
        const QString found = QStandardPaths::findExecutable(name);
        if (!found.isEmpty())
            return found;
    }

    static const QStringList fallbacks = {
        QStringLiteral("/opt/homebrew/bin/gpg"),
        QStringLiteral("/usr/local/bin/gpg"),
        QStringLiteral("/opt/local/bin/gpg"),
        QStringLiteral("/usr/local/MacGPG2/bin/gpg2"),
        QStringLiteral("/usr/bin/gpg"),
    };
    for (const QString &candidate : fallbacks) {
        if (QFileInfo(candidate).isExecutable())
            return candidate;
    }
    return {};
}

QString GpgManager::version() const
{
    if (!isAvailable())
        return QStringLiteral("gpg not found");

    QProcess process;
    process.start(m_gpgExecutable, {QStringLiteral("--version")});
    if (!process.waitForFinished(kListTimeoutMs))
        return QStringLiteral("gpg did not respond");

    const QString output = QString::fromUtf8(process.readAllStandardOutput());
    const QStringList lines = output.split(QLatin1Char('\n'), Qt::SkipEmptyParts);
    return lines.isEmpty() ? QStringLiteral("unknown") : lines.first().trimmed();
}

QList<GpgKey> GpgManager::listKeys(bool secretOnly, QString *errorOut) const
{
    QList<GpgKey> keys;
    if (!isAvailable()) {
        if (errorOut)
            *errorOut = QStringLiteral("gpg executable not found on this system.");
        return keys;
    }

    // Two passes: the requested list, plus the secret-key fingerprints so a
    // public-key listing can still be annotated with "decryptable here".
    auto runListing = [this](const QString &command, QString *error) -> QString {
        QProcess process;
        process.start(m_gpgExecutable,
                      {QStringLiteral("--batch"),
                       QStringLiteral("--no-tty"),
                       QStringLiteral("--with-colons"),
                       QStringLiteral("--fixed-list-mode"),
                       command});
        if (!process.waitForFinished(kListTimeoutMs)) {
            process.kill();
            if (error)
                *error = QStringLiteral("gpg %1 timed out.").arg(command);
            return {};
        }
        if (process.exitStatus() != QProcess::NormalExit) {
            if (error)
                *error = QStringLiteral("gpg %1 crashed.").arg(command);
            return {};
        }
        return QString::fromUtf8(process.readAllStandardOutput());
    };

    QSet<QString> secretFingerprints;
    {
        const QString secretOutput = runListing(QStringLiteral("--list-secret-keys"), nullptr);
        const QStringList lines = secretOutput.split(QLatin1Char('\n'), Qt::SkipEmptyParts);
        bool inSecretKey = false;
        for (const QString &line : lines) {
            const QStringList fields = line.split(QLatin1Char(':'));
            const QString record = colonField(fields, 0);
            if (record == QLatin1String("sec")) {
                inSecretKey = true;
            } else if (record == QLatin1String("fpr") && inSecretKey) {
                secretFingerprints.insert(colonField(fields, 9));
                inSecretKey = false;
            } else if (record == QLatin1String("ssb") || record == QLatin1String("sub")) {
                inSecretKey = false;
            }
        }
    }

    const QString listing =
        runListing(secretOnly ? QStringLiteral("--list-secret-keys") : QStringLiteral("--list-keys"),
                   errorOut);
    if (listing.isEmpty())
        return keys;

    const QStringList lines = listing.split(QLatin1Char('\n'), Qt::SkipEmptyParts);

    GpgKey current;
    bool haveKey = false;
    bool awaitingPrimaryFingerprint = false;
    bool currentUsable = false;
    bool hasEncryptionSubkey = false;

    auto flush = [&]() {
        // A recipient is only useful if it can actually receive a message:
        // either the primary key or one of its subkeys must carry 'e'.
        if (haveKey && currentUsable && hasEncryptionSubkey && !current.fingerprint.isEmpty()) {
            current.hasSecretKey = secretFingerprints.contains(current.fingerprint);
            current.keyId = current.fingerprint.right(16);
            keys.append(current);
        }
        current = GpgKey{};
        haveKey = false;
        awaitingPrimaryFingerprint = false;
        currentUsable = false;
        hasEncryptionSubkey = false;
    };

    for (const QString &line : lines) {
        const QStringList fields = line.split(QLatin1Char(':'));
        const QString record = colonField(fields, 0);

        if (record == QLatin1String("pub") || record == QLatin1String("sec")) {
            flush();
            haveKey = true;
            awaitingPrimaryFingerprint = true;
            currentUsable = validityIsUsable(colonField(fields, 1));
            current.algorithm = colonField(fields, 16);
            if (current.algorithm.isEmpty()) {
                // Older gpg reports only the numeric algo + bit length.
                current.algorithm = QStringLiteral("%1-bit").arg(colonField(fields, 2));
            }
            const qint64 epoch = colonField(fields, 5).toLongLong();
            if (epoch > 0) {
                current.created =
                    QDateTime::fromSecsSinceEpoch(epoch).date().toString(Qt::ISODate);
            }
            hasEncryptionSubkey = colonField(fields, 11).contains(QLatin1Char('e'));
        } else if (record == QLatin1String("fpr")) {
            if (haveKey && awaitingPrimaryFingerprint) {
                current.fingerprint = colonField(fields, 9);
                awaitingPrimaryFingerprint = false;
            }
        } else if (record == QLatin1String("uid")) {
            if (haveKey && current.userId.isEmpty() && validityIsUsable(colonField(fields, 1))) {
                // gpg C-escapes the uid; \x3a is the only escape that matters
                // for parsing, the rest are cosmetic.
                QString uid = colonField(fields, 9);
                uid.replace(QLatin1String("\\x3a"), QLatin1String(":"));
                current.userId = uid;
            }
        } else if (record == QLatin1String("sub") || record == QLatin1String("ssb")) {
            if (haveKey && validityIsUsable(colonField(fields, 1))
                && colonField(fields, 11).contains(QLatin1Char('e'))) {
                hasEncryptionSubkey = true;
            }
        }
    }
    flush();

    if (keys.isEmpty() && errorOut && errorOut->isEmpty()) {
        *errorOut = secretOnly
            ? QStringLiteral("No usable secret keys with an encryption subkey were found.")
            : QStringLiteral("No usable public keys with an encryption subkey were found.");
    }
    return keys;
}

GpgRecipient GpgManager::identifyRecipient(const QString &filePath) const
{
    GpgRecipient result;

    if (!isAvailable()) {
        result.error = QStringLiteral("gpg executable not found on this system.");
        return result;
    }

    const QFileInfo info(filePath);
    if (!info.exists() || !info.isFile()) {
        result.error = QStringLiteral("%1 does not exist.").arg(info.fileName());
        return result;
    }
    if (info.size() > kMaxWalletFileBytes) {
        result.error = QStringLiteral("larger than 1 MiB; not a wallet file.");
        return result;
    }

    // --list-only turns --decrypt into a dry run: gpg parses the packet
    // headers and reports what it finds on --status-fd, but never asks for a
    // passphrase and never touches (or needs) a secret key. The recipient's
    // key ID is right there in the "public-key encrypted session key"
    // packet, unencrypted — that is how gpg itself knows which secret key to
    // try at real decrypt time.
    QProcess process;
    process.start(m_gpgExecutable,
                  {QStringLiteral("--batch"),
                   QStringLiteral("--no-tty"),
                   QStringLiteral("--status-fd"), QStringLiteral("1"),
                   QStringLiteral("--decrypt"),
                   QStringLiteral("--list-only"),
                   QDir::toNativeSeparators(info.absoluteFilePath())});
    if (!process.waitForFinished(kListTimeoutMs)) {
        process.kill();
        result.error = QStringLiteral("gpg timed out.");
        return result;
    }

    const QString status = QString::fromUtf8(process.readAllStandardOutput());
    for (const QString &line : status.split(QLatin1Char('\n'), Qt::SkipEmptyParts)) {
        if (!line.startsWith(QLatin1String("[GNUPG:] ENC_TO ")))
            continue;
        const QStringList tokens = line.simplified().split(QLatin1Char(' '));
        if (tokens.size() >= 3 && tokens.at(2).size() >= 8) {
            result.keyId = tokens.at(2).toUpper();
            break;
        }
    }

    if (result.keyId.isEmpty()) {
        result.error = QStringLiteral("not a GPG-encrypted file.");
        return result;
    }
    result.ok = true;

    // Resolve to a display name if the key happens to be in the local
    // keyring. Not finding it is normal (e.g. a wallet copied in from
    // another machine) and not an error — the key ID above is still shown.
    QProcess lookup;
    lookup.start(m_gpgExecutable,
                {QStringLiteral("--batch"), QStringLiteral("--no-tty"),
                 QStringLiteral("--with-colons"), QStringLiteral("--fixed-list-mode"),
                 QStringLiteral("--list-keys"), result.keyId});
    if (lookup.waitForFinished(kListTimeoutMs) && lookup.exitCode() == 0) {
        const QString listing = QString::fromUtf8(lookup.readAllStandardOutput());
        bool inPrimaryKey = false;
        for (const QString &line : listing.split(QLatin1Char('\n'), Qt::SkipEmptyParts)) {
            const QStringList fields = line.split(QLatin1Char(':'));
            const QString record = colonField(fields, 0);
            if (record == QLatin1String("pub")) {
                inPrimaryKey = true;
            } else if (record == QLatin1String("fpr") && inPrimaryKey && result.fingerprint.isEmpty()) {
                result.fingerprint = colonField(fields, 9);
            } else if (record == QLatin1String("uid") && result.userId.isEmpty()) {
                QString uid = colonField(fields, 9);
                uid.replace(QLatin1String("\\x3a"), QLatin1String(":"));
                result.userId = uid;
            } else if (record == QLatin1String("sub") || record == QLatin1String("ssb")) {
                inPrimaryKey = false;
            }
        }
    }

    return result;
}

bool GpgManager::encryptToFile(const SecureBytes &plaintext,
                               const QString &recipientFingerprint,
                               const QString &filePath,
                               QString *errorOut) const
{
    auto fail = [errorOut](const QString &message) {
        if (errorOut)
            *errorOut = message;
        return false;
    };

    if (!isAvailable())
        return fail(QStringLiteral("gpg executable not found on this system."));
    if (recipientFingerprint.isEmpty())
        return fail(QStringLiteral("No GPG recipient key was selected."));

    const QFileInfo info(filePath);
    if (!QDir().mkpath(info.absolutePath()))
        return fail(QStringLiteral("Cannot create directory %1.").arg(info.absolutePath()));

    // Encrypt to a sibling temp path, then rename. gpg writes to stdout here
    // so we control the file bytes and never leave a half-written .bin behind.
    QProcess process;
    process.start(m_gpgExecutable,
                  {QStringLiteral("--batch"),
                   QStringLiteral("--yes"),
                   QStringLiteral("--no-tty"),
                   // The user picked this key from their own keyring by hand;
                   // requiring an OpenPGP trust signature on top of that would
                   // reject most personal keys for no security gain.
                   QStringLiteral("--trust-model"), QStringLiteral("always"),
                   QStringLiteral("--recipient"), recipientFingerprint,
                   QStringLiteral("--encrypt"),
                   QStringLiteral("--output"), QStringLiteral("-")});

    if (!process.waitForStarted(kEncryptTimeoutMs))
        return fail(QStringLiteral("Could not start gpg: %1").arg(process.errorString()));

    process.write(plaintext.chars(), static_cast<qint64>(plaintext.size()));
    process.closeWriteChannel();

    if (!process.waitForFinished(kEncryptTimeoutMs)) {
        process.kill();
        process.waitForFinished(2000);
        return fail(QStringLiteral("gpg timed out while encrypting."));
    }

    if (process.exitStatus() != QProcess::NormalExit || process.exitCode() != 0) {
        const QString stderrText = QString::fromUtf8(process.readAllStandardError()).trimmed();
        return fail(QStringLiteral("gpg failed (exit %1).\n\n%2")
                        .arg(process.exitCode())
                        .arg(stderrText.isEmpty() ? QStringLiteral("no diagnostics") : stderrText));
    }

    QByteArray ciphertext = process.readAllStandardOutput();
    if (ciphertext.isEmpty())
        return fail(QStringLiteral("gpg produced no output."));

    QSaveFile out(filePath);
    if (!out.open(QIODevice::WriteOnly)) {
        wipe(ciphertext);
        return fail(QStringLiteral("Cannot write %1: %2").arg(filePath, out.errorString()));
    }
    // Owner-only from the moment the file exists.
    out.setPermissions(QFile::ReadOwner | QFile::WriteOwner);
    const bool written = out.write(ciphertext) == ciphertext.size() && out.commit();
    wipe(ciphertext);

    if (!written)
        return fail(QStringLiteral("Failed to write %1.").arg(filePath));

    QFile::setPermissions(filePath, QFile::ReadOwner | QFile::WriteOwner);
    return true;
}

GpgDecryptOperation *GpgManager::decryptFile(const QString &filePath,
                                             std::function<void(DecryptResult)> callback,
                                             QObject *context)
{
    auto reportError = [callback](const QString &message) {
        DecryptResult result;
        result.ok = false;
        result.error = message;
        callback(std::move(result));
    };

    if (!isAvailable()) {
        reportError(QStringLiteral("gpg executable not found on this system."));
        return nullptr;
    }

    const QFileInfo info(filePath);
    if (!info.exists() || !info.isFile()) {
        reportError(QStringLiteral("%1 does not exist.").arg(filePath));
        return nullptr;
    }
    if (info.size() > kMaxWalletFileBytes) {
        reportError(QStringLiteral("%1 is larger than 1 MiB and is not a wallet file.")
                        .arg(info.fileName()));
        return nullptr;
    }

    auto *process = new QProcess(context ? context : this);
    auto *operation = new GpgDecryptOperation(process, context ? context : this);

    // No --batch here: gpg-agent must be free to raise pinentry so the user
    // can type their key passphrase.
    process->start(m_gpgExecutable,
                   {QStringLiteral("--yes"),
                    QStringLiteral("--quiet"),
                    QStringLiteral("--decrypt"),
                    QDir::toNativeSeparators(info.absoluteFilePath())});

    QPointer<GpgDecryptOperation> guard(operation);
    QObject::connect(
        process,
        &QProcess::finished,
        operation,
        [process, callback, guard](int exitCode, QProcess::ExitStatus status) {
            if (guard && guard->m_done)
                return;
            if (guard)
                guard->m_done = true;

            DecryptResult result;

            QByteArray output = process->readAllStandardOutput();
            const QString stderrText = QString::fromUtf8(process->readAllStandardError()).trimmed();

            if (guard && guard->m_cancelled) {
                result.ok = false;
                result.cancelled = true;
                result.error = QStringLiteral("Decryption cancelled.");
            } else if (status != QProcess::NormalExit) {
                result.error = QStringLiteral("gpg terminated abnormally.");
            } else if (exitCode != 0) {
                result.error = QStringLiteral("gpg could not decrypt this file (exit %1).\n\n%2%3")
                                   .arg(exitCode)
                                   .arg(stderrText.isEmpty() ? QStringLiteral("no diagnostics")
                                                             : stderrText,
                                        pinentryTtyHint(stderrText));
            } else if (output.isEmpty()) {
                result.error = QStringLiteral("gpg returned an empty plaintext.");
            } else {
                // Move straight into locked memory and scrub the QProcess copy.
                result.plaintext = SecureBytes::adopt(output);
                result.ok = true;
            }

            wipe(output);
            callback(std::move(result));

            process->deleteLater();
            if (guard)
                guard->deleteLater();
        },
        Qt::QueuedConnection);

    QObject::connect(process, &QProcess::errorOccurred, operation,
                     [process, callback, guard](QProcess::ProcessError error) {
                         if (error != QProcess::FailedToStart)
                             return; // finished() will handle every other case
                         if (guard && guard->m_done)
                             return;
                         if (guard)
                             guard->m_done = true;
                         DecryptResult result;
                         result.error =
                             QStringLiteral("Could not start gpg: %1").arg(process->errorString());
                         callback(std::move(result));
                         process->deleteLater();
                         if (guard)
                             guard->deleteLater();
                     });

    return operation;
}
