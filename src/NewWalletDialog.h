// AVXTO Wallet Manager
// Copyright (c) 2026, @REKTBuildr
//
// SPDX-License-Identifier: BSD-3-Clause
// See the LICENSE file in the project root for the full license text.

#pragma once

#include <QDialog>
#include <QList>

#include "GpgManager.h"
#include "SecureBytes.h"

class QCheckBox;
class QComboBox;
class QDialogButtonBox;
class QLabel;
class QLineEdit;

/*!
 * \brief Collects the two decisions needed to create a wallet: the file name
 *        and the GPG key the mnemonic will be encrypted to.
 *
 * In Mode::Import it also takes an existing mnemonic instead of generating
 * one. The entry field is masked like a password field — consistent with the
 * rest of the window, the full mnemonic is never rendered — so feedback on
 * typos is given by word position and checksum, not by echoing the words.
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
    enum class Mode { Generate, Import };

    NewWalletDialog(GpgManager *gpg, QString workingDirectory, Mode mode = Mode::Generate,
                    QWidget *parent = nullptr);
    ~NewWalletDialog() override;

    [[nodiscard]] QString walletName() const;
    [[nodiscard]] QString recipientFingerprint() const;

    /*!
     * Import mode only: the entered mnemonic, normalised to lowercase words
     * joined by single spaces, in locked memory. Empty in Generate mode.
     */
    [[nodiscard]] SecureBytes mnemonic() const;

    //! Import mode only: clears the entry field. Also done on destruction.
    void clearMnemonic();

private:
    void reloadKeys();
    void validate();
    [[nodiscard]] bool validateMnemonic();

    GpgManager *m_gpg;
    QString m_workingDirectory;
    Mode m_mode;

    QLineEdit *m_nameEdit;
    QLineEdit *m_mnemonicEdit = nullptr;
    QLabel *m_mnemonicStatus = nullptr;
    QCheckBox *m_allowBadChecksumCheck = nullptr;
    QLabel *m_pathLabel;
    QComboBox *m_keyCombo;
    QCheckBox *m_allKeysCheck;
    QLabel *m_keyWarning;
    QLabel *m_validationLabel;
    QDialogButtonBox *m_buttons;
};
