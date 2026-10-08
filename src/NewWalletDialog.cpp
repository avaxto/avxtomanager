// AVXTO Wallet Manager
// Copyright (c) 2026, @REKTBuildr
//
// SPDX-License-Identifier: BSD-3-Clause
// See the LICENSE file in the project root for the full license text.

#include "NewWalletDialog.h"

#include "Bip39.h"
#include "WalletFile.h"

#include <QCheckBox>
#include <QComboBox>
#include <QDialogButtonBox>
#include <QDir>
#include <QFileInfo>
#include <QFormLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QSignalBlocker>
#include <QVBoxLayout>

namespace {

// BIP-39 defines 12, 15, 18, 21 and 24 word mnemonics.
bool isBip39Length(qsizetype wordCount)
{
    return wordCount >= 12 && wordCount <= 24 && wordCount % 3 == 0;
}

void wipe(QStringList &words) noexcept
{
    for (QString &word : words)
        ::wipe(word);
    words.clear();
}

} // namespace

NewWalletDialog::NewWalletDialog(GpgManager *gpg, QString workingDirectory, Mode mode,
                                 QWidget *parent)
    : QDialog(parent)
    , m_gpg(gpg)
    , m_workingDirectory(std::move(workingDirectory))
    , m_mode(mode)
    , m_nameEdit(new QLineEdit(this))
    , m_pathLabel(new QLabel(this))
    , m_keyCombo(new QComboBox(this))
    , m_allKeysCheck(new QCheckBox(tr("Show all public keys (including keys I cannot decrypt)"), this))
    , m_keyWarning(new QLabel(this))
    , m_validationLabel(new QLabel(this))
    , m_buttons(new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this))
{
    const bool importing = m_mode == Mode::Import;
    setWindowTitle(importing ? tr("Import Mnemonic") : tr("New Wallet"));
    setModal(true);

    auto *layout = new QVBoxLayout(this);

    auto *intro = new QLabel(
        importing
            ? tr("Paste or type an existing 12-24 word BIP-39 mnemonic. It will be encrypted "
                 "to the GPG key you choose and written as a single .bin file. The words "
                 "stay masked and are never shown in this window.")
            : tr("A fresh 24-word BIP-39 mnemonic will be generated with OpenSSL's CSPRNG, "
                 "encrypted to the GPG key you choose, and written as a single .bin file."),
        this);
    intro->setWordWrap(true);
    layout->addWidget(intro);

    auto *form = new QFormLayout;
    form->setFieldGrowthPolicy(QFormLayout::ExpandingFieldsGrow);

    m_nameEdit->setPlaceholderText(tr("e.g. treasury-cold"));
    m_nameEdit->setMaxLength(64);
    form->addRow(tr("Wallet name:"), m_nameEdit);

    m_pathLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_pathLabel->setStyleSheet(QStringLiteral("color: palette(mid);"));
    form->addRow(QString(), m_pathLabel);

    if (importing) {
        m_mnemonicEdit = new QLineEdit(this);
        // Password echo also disables copy, cut and drag out of the field.
        m_mnemonicEdit->setEchoMode(QLineEdit::Password);
        m_mnemonicEdit->setMaxLength(512);
        m_mnemonicEdit->setPlaceholderText(tr("word1 word2 … word24"));
        m_mnemonicEdit->setInputMethodHints(Qt::ImhSensitiveData | Qt::ImhNoPredictiveText
                                            | Qt::ImhNoAutoUppercase | Qt::ImhHiddenText);
        form->addRow(tr("Mnemonic:"), m_mnemonicEdit);

        m_mnemonicStatus = new QLabel(this);
        m_mnemonicStatus->setWordWrap(true);
        form->addRow(QString(), m_mnemonicStatus);

        m_allowBadChecksumCheck = new QCheckBox(
            tr("Save anyway, even though the BIP-39 checksum does not match"), this);
        m_allowBadChecksumCheck->setVisible(false);
        form->addRow(QString(), m_allowBadChecksumCheck);
    }

    m_keyCombo->setSizeAdjustPolicy(QComboBox::AdjustToMinimumContentsLengthWithIcon);
    m_keyCombo->setMinimumContentsLength(40);
    form->addRow(tr("Encrypt to GPG key:"), m_keyCombo);

    layout->addLayout(form);
    layout->addWidget(m_allKeysCheck);

    m_keyWarning->setWordWrap(true);
    m_keyWarning->setStyleSheet(QStringLiteral("color: #b45309;"));
    layout->addWidget(m_keyWarning);

    m_validationLabel->setWordWrap(true);
    m_validationLabel->setStyleSheet(QStringLiteral("color: #b91c1c;"));
    layout->addWidget(m_validationLabel);

    layout->addStretch(1);
    layout->addWidget(m_buttons);

    connect(m_buttons, &QDialogButtonBox::accepted, this, &QDialog::accept);
    connect(m_buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    connect(m_nameEdit, &QLineEdit::textChanged, this, &NewWalletDialog::validate);
    connect(m_keyCombo, &QComboBox::currentIndexChanged, this, &NewWalletDialog::validate);
    connect(m_allKeysCheck, &QCheckBox::toggled, this, &NewWalletDialog::reloadKeys);
    if (importing) {
        connect(m_mnemonicEdit, &QLineEdit::textChanged, this, &NewWalletDialog::validate);
        connect(m_allowBadChecksumCheck, &QCheckBox::toggled, this, &NewWalletDialog::validate);
    }

    reloadKeys();
    resize(560, sizeHint().height());
}

NewWalletDialog::~NewWalletDialog()
{
    clearMnemonic();
}

QString NewWalletDialog::walletName() const
{
    return m_nameEdit->text().trimmed();
}

QString NewWalletDialog::recipientFingerprint() const
{
    return m_keyCombo->currentData().toString();
}

SecureBytes NewWalletDialog::mnemonic() const
{
    if (!m_mnemonicEdit)
        return {};

    QString text = m_mnemonicEdit->text();
    QString normalised = Bip39::normalise(text);
    SecureBytes result = SecureBytes::fromUtf8(normalised);
    wipe(normalised);
    wipe(text);
    return result;
}

void NewWalletDialog::clearMnemonic()
{
    if (!m_mnemonicEdit)
        return;

    // Best effort: QLineEdit keeps its own copy (and undo history), which
    // clear() releases but cannot guarantee is overwritten. Signals are
    // blocked because this also runs from the destructor.
    const QSignalBlocker blocker(m_mnemonicEdit);
    m_mnemonicEdit->clear();
}

void NewWalletDialog::reloadKeys()
{
    m_keyCombo->clear();

    QString error;
    const QList<GpgKey> keys = m_gpg->listKeys(!m_allKeysCheck->isChecked(), &error);

    for (const GpgKey &key : keys) {
        QString label = key.displayName();
        if (m_allKeysCheck->isChecked())
            label += key.hasSecretKey ? tr("  [secret key present]") : tr("  [public key only]");
        m_keyCombo->addItem(label, key.fingerprint);
    }

    if (keys.isEmpty()) {
        m_keyCombo->addItem(error.isEmpty() ? tr("No usable GPG keys found") : error, QString());
        m_keyCombo->setEnabled(false);
    } else {
        m_keyCombo->setEnabled(true);
    }

    m_keyWarning->setVisible(m_allKeysCheck->isChecked());
    m_keyWarning->setText(
        tr("Warning: encrypting to a key whose secret half is not on this machine means this "
           "application will not be able to reopen the wallet here."));

    validate();
}

void NewWalletDialog::validate()
{
    const QString name = walletName();
    QString reason;
    bool ok = WalletFile::isValidWalletName(name, &reason);

    QString targetPath;
    if (ok) {
        targetPath = QDir(m_workingDirectory).filePath(name + QStringLiteral(".bin"));
        if (QFileInfo::exists(targetPath)) {
            ok = false;
            reason = tr("%1.bin already exists in the working directory.").arg(name);
        }
    }

    m_pathLabel->setText(targetPath.isEmpty()
                             ? QDir::toNativeSeparators(
                                   QDir(m_workingDirectory).filePath(QStringLiteral("<name>.bin")))
                             : QDir::toNativeSeparators(targetPath));

    if (ok && recipientFingerprint().isEmpty()) {
        ok = false;
        reason = tr("Select a GPG key to encrypt the mnemonic to.");
    }

    // The mnemonic has its own status line, so it only gates the OK button
    // and never overwrites a name/key problem in the validation label.
    const bool mnemonicOk = m_mode != Mode::Import || validateMnemonic();

    m_validationLabel->setText(name.isEmpty() ? QString() : reason);
    m_validationLabel->setVisible(!m_validationLabel->text().isEmpty());
    m_buttons->button(QDialogButtonBox::Ok)->setEnabled(ok && mnemonicOk);
}

bool NewWalletDialog::validateMnemonic()
{
    auto report = [this](bool ok, const QString &message) {
        m_mnemonicStatus->setText(message);
        m_mnemonicStatus->setStyleSheet(ok ? QStringLiteral("color: #15803d;")
                                           : QStringLiteral("color: #b91c1c;"));
        return ok;
    };

    // The override only applies to the mnemonic it was ticked for; hiding it
    // also unticks it so a later bad checksum has to be acknowledged afresh.
    auto offerOverride = [this](bool offer) {
        if (!offer) {
            const QSignalBlocker blocker(m_allowBadChecksumCheck);
            m_allowBadChecksumCheck->setChecked(false);
        }
        m_allowBadChecksumCheck->setVisible(offer);
    };

    QString text = m_mnemonicEdit->text();
    QStringList words = Bip39::splitWords(text);
    wipe(text);

    const qsizetype count = words.size();
    if (count == 0) {
        offerOverride(false);
        m_mnemonicStatus->clear();
        return false;
    }

    // Report unknown words by position only, so a typo can be found
    // without the words themselves ever appearing on screen.
    const QStringList &list = Bip39::wordlist();
    QStringList unknown;
    for (qsizetype i = 0; i < count; ++i) {
        if (!list.contains(words.at(i)))
            unknown.append(QString::number(i + 1));
    }

    if (!unknown.isEmpty()) {
        offerOverride(false);
        wipe(words);
        return report(false, tr("%n word(s) not in the BIP-39 English list, at position(s) %1.",
                                "", static_cast<int>(unknown.size()))
                                 .arg(unknown.join(QStringLiteral(", "))));
    }

    if (!isBip39Length(count)) {
        offerOverride(false);
        wipe(words);
        return report(false, tr("%n word(s) entered; a BIP-39 mnemonic has 12, 15, 18, 21 "
                                "or 24 words.", "", static_cast<int>(count)));
    }

    QString normalised = words.join(QLatin1Char(' '));
    wipe(words);
    const bool checksumValid = Bip39::validate(normalised);
    wipe(normalised);

    offerOverride(!checksumValid);
    if (checksumValid)
        return report(true, tr("%n words, checksum valid.", "", static_cast<int>(count)));

    // Every word is real but the checksum fails: almost always a mistyped
    // or swapped word, occasionally a mnemonic from a non-standard tool.
    report(false, tr("%n words, but the BIP-39 checksum does not match. Check for a wrong "
                     "or swapped word.", "", static_cast<int>(count)));
    return m_allowBadChecksumCheck->isChecked();
}
