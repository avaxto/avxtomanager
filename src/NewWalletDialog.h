// AVXTO Wallet Manager
// Copyright (c) 2026, @REKTBuildr
//
// SPDX-License-Identifier: BSD-3-Clause
// See the LICENSE file in the project root for the full license text.

#pragma once

#include <QDialog>
#include <QList>

#include "GpgManager.h"

class QCheckBox;
class QComboBox;
class QDialogButtonBox;
class QLabel;
class QLineEdit;

/*!
 * \brief Collects the two decisions needed to create a wallet: the file name
 *        and the GPG key the mnemonic will be encrypted to.
 *
 * The key list defaults to keys whose secret half is present on this machine,
 * because a wallet encrypted to a key you cannot decrypt is an elaborate way
 * of destroying a mnemonic. The full public keyring is one checkbox away for
 * the escrow/offline-key case, with a warning attached.
 */
class NewWalletDialog : public QDialog
{
    Q_OBJECT

public:
    NewWalletDialog(GpgManager *gpg, QString workingDirectory, QWidget *parent = nullptr);

    [[nodiscard]] QString walletName() const;
    [[nodiscard]] QString recipientFingerprint() const;

private:
    void reloadKeys();
    void validate();

    GpgManager *m_gpg;
    QString m_workingDirectory;

    QLineEdit *m_nameEdit;
    QLabel *m_pathLabel;
    QComboBox *m_keyCombo;
    QCheckBox *m_allKeysCheck;
    QLabel *m_keyWarning;
    QLabel *m_validationLabel;
    QDialogButtonBox *m_buttons;
};
