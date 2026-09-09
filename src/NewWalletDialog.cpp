// AVXTO Wallet Manager
// Copyright (c) 2026, @REKTBuildr
//
// SPDX-License-Identifier: BSD-3-Clause
// See the LICENSE file in the project root for the full license text.

#include "NewWalletDialog.h"

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
#include <QVBoxLayout>

NewWalletDialog::NewWalletDialog(GpgManager *gpg, QString workingDirectory, QWidget *parent)
    : QDialog(parent)
    , m_gpg(gpg)
    , m_workingDirectory(std::move(workingDirectory))
    , m_nameEdit(new QLineEdit(this))
    , m_pathLabel(new QLabel(this))
    , m_keyCombo(new QComboBox(this))
    , m_allKeysCheck(new QCheckBox(tr("Show all public keys (including keys I cannot decrypt)"), this))
    , m_keyWarning(new QLabel(this))
    , m_validationLabel(new QLabel(this))
    , m_buttons(new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this))
{
    setWindowTitle(tr("New Wallet"));
    setModal(true);

    auto *layout = new QVBoxLayout(this);

    auto *intro = new QLabel(
        tr("A fresh 24-word BIP-39 mnemonic will be generated with OpenSSL's CSPRNG, "
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

    reloadKeys();
    resize(560, sizeHint().height());
}

QString NewWalletDialog::walletName() const
{
    return m_nameEdit->text().trimmed();
}

QString NewWalletDialog::recipientFingerprint() const
{
    return m_keyCombo->currentData().toString();
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

    m_validationLabel->setText(name.isEmpty() ? QString() : reason);
    m_validationLabel->setVisible(!m_validationLabel->text().isEmpty());
    m_buttons->button(QDialogButtonBox::Ok)->setEnabled(ok);
}
