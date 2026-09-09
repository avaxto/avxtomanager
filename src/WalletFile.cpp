// AVXTO Wallet Manager
// Copyright (c) 2026, @REKTBuildr
//
// SPDX-License-Identifier: BSD-3-Clause
// See the LICENSE file in the project root for the full license text.

#include "WalletFile.h"

#include "Bip39.h"

#include <QDateTime>
#include <QJsonDocument>
#include <QJsonObject>
#include <QRegularExpression>

namespace WalletFile {
namespace {

constexpr int kFormatVersion = 1;

} // namespace

SecureBytes serialise(const SecureBytes &mnemonic)
{
    // QJsonDocument allocates outside our locked pages, so the intermediate
    // objects are wiped as soon as the bytes are copied into SecureBytes.
    QString mnemonicText = mnemonic.toQString();

    QJsonObject object;
    object.insert(QStringLiteral("format"), QStringLiteral("avxto-wallet"));
    object.insert(QStringLiteral("version"), kFormatVersion);
    object.insert(QStringLiteral("created"),
                  QDateTime::currentDateTimeUtc().toString(Qt::ISODate));
    object.insert(QStringLiteral("wordCount"),
                  static_cast<int>(Bip39::splitWords(mnemonicText).size()));
    object.insert(QStringLiteral("mnemonic"), mnemonicText);

    QByteArray json = QJsonDocument(object).toJson(QJsonDocument::Indented);
    SecureBytes payload = SecureBytes::adopt(json);

    object = QJsonObject{};
    wipe(mnemonicText);
    return payload;
}

bool parse(const SecureBytes &plaintext, Contents *out, QString *errorOut)
{
    auto fail = [errorOut](const QString &message) {
        if (errorOut)
            *errorOut = message;
        return false;
    };

    if (!out)
        return fail(QStringLiteral("internal error: no output buffer"));

    QByteArray raw(plaintext.chars(), static_cast<qsizetype>(plaintext.size()));

    QString mnemonicText;
    QString created;

    QJsonParseError parseError{};
    const QJsonDocument document = QJsonDocument::fromJson(raw, &parseError);
    if (parseError.error == QJsonParseError::NoError && document.isObject()) {
        const QJsonObject object = document.object();
        mnemonicText = object.value(QStringLiteral("mnemonic")).toString();
        created = object.value(QStringLiteral("created")).toString();
        if (mnemonicText.isEmpty()) {
            wipe(raw);
            return fail(QStringLiteral("The wallet file has no \"mnemonic\" field."));
        }
    } else {
        // Fall back to treating the whole payload as a bare mnemonic.
        mnemonicText = QString::fromUtf8(raw);
    }
    wipe(raw);

    const QStringList words = Bip39::splitWords(mnemonicText);
    wipe(mnemonicText);

    if (words.isEmpty())
        return fail(QStringLiteral("The decrypted file contains no words."));
    if (words.size() < 12 || words.size() > 24)
        return fail(QStringLiteral("Expected a 12-24 word mnemonic, found %1 words.")
                        .arg(words.size()));

    QString normalised = words.join(QLatin1Char(' '));
    out->mnemonic = SecureBytes::fromUtf8(normalised);
    out->wordCount = static_cast<int>(words.size());
    out->created = created;
    out->checksumValid = Bip39::validate(normalised);
    wipe(normalised);

    return true;
}

bool isValidWalletName(const QString &name, QString *reasonOut)
{
    auto reject = [reasonOut](const QString &message) {
        if (reasonOut)
            *reasonOut = message;
        return false;
    };

    if (name.isEmpty())
        return reject(QStringLiteral("Enter a name for the wallet."));
    if (name.size() > 64)
        return reject(QStringLiteral("Wallet names are limited to 64 characters."));

    // Deliberately strict: the name becomes a filename in the working
    // directory, so anything that could escape it or confuse the shell is out.
    static const QRegularExpression allowed(QStringLiteral("^[A-Za-z0-9][A-Za-z0-9._-]*$"));
    if (!allowed.match(name).hasMatch()) {
        return reject(QStringLiteral(
            "Use letters, digits, dot, dash or underscore, starting with a letter or digit."));
    }
    if (name.contains(QLatin1String("..")))
        return reject(QStringLiteral("Wallet names cannot contain \"..\"."));
    if (name.endsWith(QLatin1String(".bin"), Qt::CaseInsensitive))
        return reject(QStringLiteral("Leave off the .bin suffix; it is added automatically."));

    return true;
}

} // namespace WalletFile
