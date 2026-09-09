// AVXTO Wallet Manager
// Copyright (c) 2026, @REKTBuildr
//
// SPDX-License-Identifier: BSD-3-Clause
// See the LICENSE file in the project root for the full license text.

#pragma once

#include <QMainWindow>
#include <QString>

#include "GpgManager.h"
#include "SessionRegistry.h"

class QAction;
class QFileSystemWatcher;
class QLabel;
class QLineEdit;
class QListWidget;
class QListWidgetItem;
class QPlainTextEdit;
class QPushButton;
class QToolButton;
class RpcServer;

/*!
 * \brief The application window: working directory, wallet list, and the
 *        details of whichever wallet is currently selected.
 *
 * The full mnemonic is never rendered in the GUI. The window shows the file
 * name, the first and last word, and the session password; anything more
 * has to go through the RPC endpoint, where it is at least gated by a
 * credential and logged.
 */
class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow() override;

protected:
    void closeEvent(QCloseEvent *event) override;

private:
    void buildUi();
    void buildMenus();
    void restoreSettings();

    void chooseWorkingDirectory();
    void setWorkingDirectory(const QString &path, bool persist = true);
    void refreshWalletList();

    void createWallet();
    void openSelectedWallet();
    void closeSelectedWallet();
    void closeAllWallets();

    void updateDetails();
    void updateActions();
    void copySessionPassword();
    void copyRpcExample();

    [[nodiscard]] QString selectedFilePath() const;
    [[nodiscard]] QString selectedFileName() const;

    void appendLog(const QString &line);
    void showError(const QString &title, const QString &message);

    GpgManager m_gpg;
    SessionRegistry m_registry;
    RpcServer *m_rpc = nullptr;
    QFileSystemWatcher *m_watcher = nullptr;
    GpgDecryptOperation *m_activeDecrypt = nullptr;

    QString m_workingDirectory;

    QLineEdit *m_directoryEdit = nullptr;
    QListWidget *m_walletList = nullptr;

    QLabel *m_fileNameValue = nullptr;
    QLabel *m_statusValue = nullptr;
    QLabel *m_firstWordValue = nullptr;
    QLabel *m_lastWordValue = nullptr;
    QLabel *m_wordCountValue = nullptr;
    QLabel *m_openedAtValue = nullptr;
    QLineEdit *m_passwordEdit = nullptr;
    QToolButton *m_revealButton = nullptr;
    QPushButton *m_copyPasswordButton = nullptr;

    QPushButton *m_openButton = nullptr;
    QPushButton *m_closeButton = nullptr;
    QPushButton *m_newButton = nullptr;

    QLabel *m_endpointLabel = nullptr;
    QPlainTextEdit *m_logView = nullptr;

    QAction *m_newAction = nullptr;
    QAction *m_openAction = nullptr;
    QAction *m_closeAction = nullptr;
    QAction *m_closeAllAction = nullptr;
};
