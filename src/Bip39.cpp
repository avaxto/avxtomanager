// AVXTO Wallet Manager
// Copyright (c) 2026, @REKTBuildr
//
// SPDX-License-Identifier: BSD-3-Clause
// See the LICENSE file in the project root for the full license text.

#include "Bip39.h"

#include "SessionCrypto.h"

#include <QFile>
#include <QRegularExpression>

#include <openssl/sha.h>

#include <array>
#include <cstring>
#include <stdexcept>
#include <vector>

namespace Bip39 {
namespace {

constexpr int kBitsPerWord = 11;
constexpr int kWordlistSize = 1 << kBitsPerWord; // 2048

QStringList loadWordlist()
{
    QFile file(QStringLiteral(":/bip39/english.txt"));
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text))
        throw std::runtime_error("bundled BIP-39 wordlist is missing from the resource bundle");

    const QString contents = QString::fromUtf8(file.readAll());
    QStringList words = contents.split(QLatin1Char('\n'), Qt::SkipEmptyParts);
    for (QString &word : words)
        word = word.trimmed();
    words.removeAll(QString());

    if (words.size() != kWordlistSize) {
        throw std::runtime_error("bundled BIP-39 wordlist has the wrong size; expected 2048 words");
    }
    return words;
}

/*!
 * Maps a mnemonic back to its entropy+checksum bit string and verifies the
 * checksum. Returns false for unknown words or a bad checksum.
 */
bool checksumIsValid(const QStringList &words)
{
    const int wordCount = static_cast<int>(words.size());
    // BIP-39 defines 12, 15, 18, 21 and 24 word mnemonics.
    if (wordCount < 12 || wordCount > 24 || wordCount % 3 != 0)
        return false;

    const QStringList &list = wordlist();

    const int totalBits = wordCount * kBitsPerWord;
    const int checksumBits = totalBits / 33;
    const int entropyBits = totalBits - checksumBits;

    std::vector<unsigned char> bits;
    bits.reserve(static_cast<std::size_t>(totalBits));
    for (const QString &word : words) {
        const qsizetype index = list.indexOf(word);
        if (index < 0)
            return false;
        for (int bit = kBitsPerWord - 1; bit >= 0; --bit)
            bits.push_back(static_cast<unsigned char>((index >> bit) & 1));
    }

    std::vector<unsigned char> entropy(static_cast<std::size_t>(entropyBits / 8), 0);
    for (int i = 0; i < entropyBits; ++i) {
        if (bits[static_cast<std::size_t>(i)])
            entropy[static_cast<std::size_t>(i / 8)] |= static_cast<unsigned char>(1 << (7 - (i % 8)));
    }

    unsigned char digest[SHA256_DIGEST_LENGTH] = {};
    SHA256(entropy.data(), entropy.size(), digest);

    bool ok = true;
    for (int i = 0; i < checksumBits; ++i) {
        const unsigned char expected =
            static_cast<unsigned char>((digest[i / 8] >> (7 - (i % 8))) & 1);
        if (bits[static_cast<std::size_t>(entropyBits + i)] != expected)
            ok = false;
    }

    wipe(entropy.data(), entropy.size());
    wipe(bits.data(), bits.size());
    wipe(digest, sizeof(digest));
    return ok;
}

} // namespace

const QStringList &wordlist()
{
    static const QStringList words = loadWordlist();
    return words;
}

SecureBytes generateMnemonic()
{
    const QStringList &list = wordlist();

    SecureBytes entropy = SessionCrypto::randomBytes(kEntropyBytes);

    unsigned char digest[SHA256_DIGEST_LENGTH] = {};
    SHA256(entropy.data(), entropy.size(), digest);

    // 256 entropy bits + 8 checksum bits = 264 = 24 * 11.
    constexpr int kChecksumBits = kEntropyBytes * 8 / 32;
    constexpr int kTotalBits = kEntropyBytes * 8 + kChecksumBits;

    std::array<unsigned char, kTotalBits> bits{};
    for (int i = 0; i < kEntropyBytes * 8; ++i)
        bits[static_cast<std::size_t>(i)] =
            static_cast<unsigned char>((entropy.data()[i / 8] >> (7 - (i % 8))) & 1);
    for (int i = 0; i < kChecksumBits; ++i)
        bits[static_cast<std::size_t>(kEntropyBytes * 8 + i)] =
            static_cast<unsigned char>((digest[i / 8] >> (7 - (i % 8))) & 1);

    // Assemble straight into locked memory: the mnemonic never exists as a
    // QString/QStringList that Qt might copy or keep in a shared pool.
    SecureBytes mnemonic(kWordCount * 9); // longest BIP-39 word is 8 chars + separator
    std::size_t offset = 0;
    for (int w = 0; w < kWordCount; ++w) {
        int index = 0;
        for (int bit = 0; bit < kBitsPerWord; ++bit)
            index = (index << 1) | bits[static_cast<std::size_t>(w * kBitsPerWord + bit)];

        const QByteArray word = list.at(index).toLatin1();
        if (offset > 0)
            mnemonic.chars()[offset++] = ' ';
        std::memcpy(mnemonic.chars() + offset, word.constData(), static_cast<std::size_t>(word.size()));
        offset += static_cast<std::size_t>(word.size());
    }

    wipe(bits.data(), bits.size());
    wipe(digest, sizeof(digest));

    // Trim to the bytes actually used.
    SecureBytes exact(mnemonic.data(), offset);
    return exact;
}

QStringList splitWords(const QString &mnemonic)
{
    static const QRegularExpression whitespace(QStringLiteral("\\s+"));
    QStringList words = mnemonic.trimmed().toLower().split(whitespace, Qt::SkipEmptyParts);
    return words;
}

QString normalise(const QString &mnemonic)
{
    return splitWords(mnemonic).join(QLatin1Char(' '));
}

bool validate(const QString &mnemonic)
{
    return checksumIsValid(splitWords(mnemonic));
}

} // namespace Bip39
