// AVXTO Wallet Manager
// Copyright (c) 2026, @REKTBuildr
//
// SPDX-License-Identifier: BSD-3-Clause
// See the LICENSE file in the project root for the full license text.

#include "MainWindow.h"

#include <QApplication>
#include <QMessageBox>
#include <QStyleHints>

#include <openssl/crypto.h>
#include <openssl/rand.h>

#include <exception>

namespace {

/*!
 * Fails fast if libcrypto's RNG is not usable. Every secret this program
 * produces — mnemonics, session passwords, salts, IVs — comes from here, so
 * starting up with a broken RNG would silently produce guessable wallets.
 */
bool opensslRandomIsUsable(QString *errorOut)
{
    unsigned char probe[32] = {};
    if (RAND_status() != 1) {
        *errorOut = QStringLiteral("OpenSSL's random number generator is not seeded.");
        return false;
    }
    if (RAND_bytes(probe, sizeof(probe)) != 1) {
        *errorOut = QStringLiteral("OpenSSL's RAND_bytes() failed.");
        return false;
    }
    OPENSSL_cleanse(probe, sizeof(probe));
    return true;
}

} // namespace

int main(int argc, char *argv[])
{
    QApplication application(argc, argv);

    QCoreApplication::setOrganizationName(QStringLiteral("AVXTO"));
    QCoreApplication::setOrganizationDomain(QStringLiteral("avax.to"));
    QCoreApplication::setApplicationName(QStringLiteral("AVXTO Wallet Manager"));
    QCoreApplication::setApplicationVersion(QString::fromLatin1(AVXTO_VERSION));

    QString rngError;
    if (!opensslRandomIsUsable(&rngError)) {
        QMessageBox::critical(
            nullptr,
            QCoreApplication::applicationName(),
            QStringLiteral("%1\n\nRefusing to start: wallets generated now would not be secure.")
                .arg(rngError));
        return 2;
    }

    try {
        MainWindow window;
        window.show();
        return QApplication::exec();
    } catch (const std::exception &error) {
        QMessageBox::critical(nullptr,
                              QCoreApplication::applicationName(),
                              QStringLiteral("Fatal error during startup:\n\n%1")
                                  .arg(QString::fromUtf8(error.what())));
        return 1;
    }
}
