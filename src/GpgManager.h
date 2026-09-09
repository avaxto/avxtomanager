// AVXTO Wallet Manager
// Copyright (c) 2026, @REKTBuildr
//
// SPDX-License-Identifier: BSD-3-Clause
// See the LICENSE file in the project root for the full license text.

#pragma once

#include "SecureBytes.h"

#include <QObject>
#include <QString>
#include <QStringList>

#include <functional>
#include <memory>

class QProcess;
class GpgManager;

/*!
 * \brief Handle for an in-flight asynchronous gpg decryption.
 *
 * Owned by the QObject context passed to GpgManager::decryptFile() and
 * deleted once the callback has run. Calling cancel() terminates gpg, which
 * also dismisses any pinentry dialog it raised.
 */
class GpgDecryptOperation : public QObject
{
    Q_OBJECT

public:
    ~GpgDecryptOperation() override;
    void cancel();

private:
    friend class GpgManager;
    GpgDecryptOperation(QProcess *process, QObject *parent);

    QProcess *m_process;
    bool m_cancelled = false;
    bool m_done = false;  //!< guards against a double callback
};

/*!
 * \brief A GPG key usable as an encryption recipient.
 */
struct GpgKey
{
    QString fingerprint;   //!< 40 hex characters; used as the recipient argument
    QString keyId;         //!< trailing 16 characters, for display
    QString userId;        //!< primary uid, e.g. "Name <mail@example.com>"
    QString algorithm;     //!< e.g. "rsa4096", "ed25519"
    QString created;       //!< ISO date
    bool hasSecretKey = false; //!< whether this machine can also decrypt

    [[nodiscard]] QString displayName() const;
};

/*!
 * \brief Drives the local gpg(1) binary for wallet file encryption/decryption.
 *
 * Everything runs through QProcess against the user's real GnuPG home, so
 * passphrase entry is handled by the user's own gpg-agent/pinentry — this
 * application never sees, prompts for, or stores a GPG passphrase.
 *
 * Decryption is asynchronous on purpose: pinentry can sit waiting for a
 * human for a long time, and blocking the GUI thread on waitForFinished()
 * would freeze the window behind the passphrase dialog.
 */
class GpgManager : public QObject
{
    Q_OBJECT

public:
    explicit GpgManager(QObject *parent = nullptr);
    ~GpgManager() override;

    //! Absolute path of the gpg binary, or an empty string if none was found.
    [[nodiscard]] QString gpgExecutable() const { return m_gpgExecutable; }
    [[nodiscard]] bool isAvailable() const { return !m_gpgExecutable.isEmpty(); }

    //! Overrides binary discovery (settings / --gpg-path).
    void setGpgExecutable(const QString &path);

    //! "gpg (GnuPG) 2.x.y" or an error string. Runs synchronously; it is fast
    //! and does not touch the keyring.
    [[nodiscard]] QString version() const;

    /*!
     * Lists keys that can be used as encryption recipients.
     *
     * \param secretOnly restrict to keys whose private half is present, so the
     *        wallet stays decryptable on this machine. Recommended.
     *
     * Revoked, expired, disabled and invalid keys are filtered out, as are
     * keys with no encryption-capable subkey.
     */
    [[nodiscard]] QList<GpgKey> listKeys(bool secretOnly, QString *errorOut = nullptr) const;

    /*!
     * Encrypts \a plaintext to \a recipientFingerprint and writes \a filePath.
     *
     * Synchronous: encryption needs only the public key, so gpg never prompts
     * and returns in milliseconds. Writes to a temporary file in the same
     * directory and renames on success, so a failure cannot truncate an
     * existing wallet.
     */
    [[nodiscard]] bool encryptToFile(const SecureBytes &plaintext,
                                     const QString &recipientFingerprint,
                                     const QString &filePath,
                                     QString *errorOut = nullptr) const;

    //! Outcome handed to the decryptFile() callback.
    struct DecryptResult
    {
        bool ok = false;
        SecureBytes plaintext;
        QString error;
        bool cancelled = false;
    };

    /*!
     * Decrypts  filePath asynchronously, invoking  callback on the calling
     * thread when gpg exits. The returned handle cancels the operation when
     * cancel() is called on it; it is nullptr if gpg could not be started at
     * all, in which case  callback has already run with an error.
     */
    GpgDecryptOperation *decryptFile(const QString &filePath,
                                     std::function<void(DecryptResult)> callback,
                                     QObject *context = nullptr);

private:
    static QString findGpgExecutable();

    QString m_gpgExecutable;
};
