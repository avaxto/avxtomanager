// AVXTO Wallet Manager
// Copyright (c) 2026, @REKTBuildr
//
// SPDX-License-Identifier: BSD-3-Clause
// See the LICENSE file in the project root for the full license text.

#include "MainWindow.h"

#include "Bip39.h"
#include "RpcServer.h"
#include "SecureBytes.h"
#include "SessionCrypto.h"
#include "WalletFile.h"

#include <QApplication>
#include <QClipboard>
#include <QCloseEvent>
#include <QDir>
#include <QFileDialog>
#include <QFileSystemWatcher>
#include <QFontDatabase>
#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QMenuBar>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QProgressDialog>
#include <QPushButton>
#include <QSettings>
#include <QSplitter>
#include <QStandardPaths>
#include <QStatusBar>
#include <QToolButton>
#include <QVBoxLayout>

namespace {

constexpr auto kSettingsWorkingDirectory = "workingDirectory";
constexpr auto kSettingsGeometry = "geometry";
constexpr auto kSettingsState = "windowState";

QString placeholder()
{
    return QStringLiteral("—");
}

QFont monospaceFont()
{
    return QFontDatabase::systemFont(QFontDatabase::FixedFont);
}

} // namespace

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , m_rpc(new RpcServer(&m_registry, this))
    , m_watcher(new QFileSystemWatcher(this))
{
    setWindowTitle(tr("AVXTO Wallet Manager"));

    buildUi();
    buildMenus();

    connect(m_watcher, &QFileSystemWatcher::directoryChanged, this, &MainWindow::refreshWalletList);
    connect(&m_registry, &SessionRegistry::changed, this, [this] {
        refreshWalletList();
        updateDetails();
    });
    connect(m_rpc, &RpcServer::requestLogged, this, &MainWindow::appendLog);

    if (m_rpc->start()) {
        m_endpointLabel->setText(m_rpc->endpoint());
        appendLog(tr("JSON-RPC endpoint listening on %1").arg(m_rpc->endpoint()));
    } else {
        m_endpointLabel->setText(tr("failed to bind a loopback port"));
        appendLog(tr("ERROR: could not start the JSON-RPC listener."));
    }

    if (!m_gpg.isAvailable()) {
        appendLog(tr("ERROR: gpg was not found on PATH. Wallet creation and opening are disabled."));
    } else {
        appendLog(tr("Using %1 (%2)").arg(m_gpg.gpgExecutable(), m_gpg.version()));
    }

    restoreSettings();
    updateActions();
    updateDetails();
}

MainWindow::~MainWindow() = default;

void MainWindow::buildUi()
{
    auto *central = new QWidget(this);
    auto *outer = new QVBoxLayout(central);

    // --- working directory -------------------------------------------------
    auto *directoryRow = new QHBoxLayout;
    directoryRow->addWidget(new QLabel(tr("Working directory:"), this));

    m_directoryEdit = new QLineEdit(this);
    m_directoryEdit->setReadOnly(true);
    m_directoryEdit->setPlaceholderText(tr("Choose a folder to hold your .bin wallet files"));
    directoryRow->addWidget(m_directoryEdit, 1);

    auto *browseButton = new QPushButton(tr("Browse…"), this);
    connect(browseButton, &QPushButton::clicked, this, &MainWindow::chooseWorkingDirectory);
    directoryRow->addWidget(browseButton);

    auto *refreshButton = new QPushButton(tr("Refresh"), this);
    connect(refreshButton, &QPushButton::clicked, this, &MainWindow::refreshWalletList);
    directoryRow->addWidget(refreshButton);

    outer->addLayout(directoryRow);

    // --- wallet list / details --------------------------------------------
    auto *splitter = new QSplitter(Qt::Horizontal, this);

    auto *listPanel = new QWidget(splitter);
    auto *listLayout = new QVBoxLayout(listPanel);
    listLayout->setContentsMargins(0, 0, 0, 0);
    listLayout->addWidget(new QLabel(tr("Wallets (double-click to decrypt):"), listPanel));

    m_walletList = new QListWidget(listPanel);
    m_walletList->setSelectionMode(QAbstractItemView::SingleSelection);
    m_walletList->setAlternatingRowColors(true);
    connect(m_walletList, &QListWidget::itemSelectionChanged, this, [this] {
        updateDetails();
        updateActions();
    });
    connect(m_walletList, &QListWidget::itemDoubleClicked, this, [this](QListWidgetItem *) {
        openSelectedWallet();
    });
    listLayout->addWidget(m_walletList, 1);

    auto *listButtons = new QHBoxLayout;
    m_newButton = new QPushButton(tr("New Wallet…"), listPanel);
    connect(m_newButton, &QPushButton::clicked, this, &MainWindow::createWallet);
    listButtons->addWidget(m_newButton);

    m_importButton = new QPushButton(tr("Import…"), listPanel);
    m_importButton->setToolTip(tr("Save an existing mnemonic as a GPG-encrypted wallet"));
    connect(m_importButton, &QPushButton::clicked, this, &MainWindow::importWallet);
    listButtons->addWidget(m_importButton);

    m_openButton = new QPushButton(tr("Open"), listPanel);
    connect(m_openButton, &QPushButton::clicked, this, &MainWindow::openSelectedWallet);
    listButtons->addWidget(m_openButton);

    m_closeButton = new QPushButton(tr("Close"), listPanel);
    connect(m_closeButton, &QPushButton::clicked, this, &MainWindow::closeSelectedWallet);
    listButtons->addWidget(m_closeButton);
    listLayout->addLayout(listButtons);

    splitter->addWidget(listPanel);

    // --- details -----------------------------------------------------------
    auto *detailPanel = new QWidget(splitter);
    auto *detailLayout = new QVBoxLayout(detailPanel);
    detailLayout->setContentsMargins(0, 0, 0, 0);

    auto *walletGroup = new QGroupBox(tr("Selected wallet"), detailPanel);
    auto *walletForm = new QFormLayout(walletGroup);

    auto makeValueLabel = [this] {
        auto *label = new QLabel(placeholder(), this);
        label->setTextInteractionFlags(Qt::TextSelectableByMouse);
        return label;
    };

    m_fileNameValue = makeValueLabel();
    m_fileNameValue->setFont(monospaceFont());
    walletForm->addRow(tr("File:"), m_fileNameValue);

    m_encryptedToValue = makeValueLabel();
    m_encryptedToValue->setWordWrap(true);
    walletForm->addRow(tr("Encrypted to:"), m_encryptedToValue);

    m_statusValue = makeValueLabel();
    walletForm->addRow(tr("Status:"), m_statusValue);

    m_firstWordValue = makeValueLabel();
    m_firstWordValue->setFont(monospaceFont());
    walletForm->addRow(tr("First word:"), m_firstWordValue);

    m_lastWordValue = makeValueLabel();
    m_lastWordValue->setFont(monospaceFont());
    walletForm->addRow(tr("Last word:"), m_lastWordValue);

    m_wordCountValue = makeValueLabel();
    walletForm->addRow(tr("Words:"), m_wordCountValue);

    m_openedAtValue = makeValueLabel();
    walletForm->addRow(tr("Opened:"), m_openedAtValue);

    detailLayout->addWidget(walletGroup);

    // --- session password ---------------------------------------------------
    auto *sessionGroup = new QGroupBox(tr("Session password"), detailPanel);
    auto *sessionLayout = new QVBoxLayout(sessionGroup);

    auto *sessionHint = new QLabel(
        tr("Generated fresh each time this wallet is opened. It is the key to the "
           "in-memory AES-256-GCM copy of the mnemonic and the credential for the "
           "JSON-RPC endpoint. Closing the wallet destroys it."),
        sessionGroup);
    sessionHint->setWordWrap(true);
    sessionLayout->addWidget(sessionHint);

    auto *passwordRow = new QHBoxLayout;
    m_passwordEdit = new QLineEdit(sessionGroup);
    m_passwordEdit->setReadOnly(true);
    m_passwordEdit->setEchoMode(QLineEdit::Password);
    m_passwordEdit->setFont(monospaceFont());
    m_passwordEdit->setPlaceholderText(tr("open a wallet to generate one"));
    passwordRow->addWidget(m_passwordEdit, 1);

    m_revealButton = new QToolButton(sessionGroup);
    m_revealButton->setText(tr("Reveal"));
    m_revealButton->setCheckable(true);
    connect(m_revealButton, &QToolButton::toggled, this, [this](bool revealed) {
        m_passwordEdit->setEchoMode(revealed ? QLineEdit::Normal : QLineEdit::Password);
        m_revealButton->setText(revealed ? tr("Hide") : tr("Reveal"));
    });
    passwordRow->addWidget(m_revealButton);

    m_copyPasswordButton = new QPushButton(tr("Copy"), sessionGroup);
    connect(m_copyPasswordButton, &QPushButton::clicked, this, &MainWindow::copySessionPassword);
    passwordRow->addWidget(m_copyPasswordButton);

    sessionLayout->addLayout(passwordRow);
    detailLayout->addWidget(sessionGroup);

    // --- RPC ---------------------------------------------------------------
    auto *rpcGroup = new QGroupBox(tr("JSON-RPC endpoint"), detailPanel);
    auto *rpcLayout = new QVBoxLayout(rpcGroup);

    auto *endpointRow = new QHBoxLayout;
    m_endpointLabel = new QLabel(tr("starting…"), rpcGroup);
    m_endpointLabel->setFont(monospaceFont());
    m_endpointLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    endpointRow->addWidget(m_endpointLabel, 1);

    auto *copyEndpoint = new QPushButton(tr("Copy"), rpcGroup);
    connect(copyEndpoint, &QPushButton::clicked, this, &MainWindow::copyRpcEndpoint);
    endpointRow->addWidget(copyEndpoint);

    auto *copyCurl = new QPushButton(tr("Copy curl example"), rpcGroup);
    connect(copyCurl, &QPushButton::clicked, this, &MainWindow::copyRpcExample);
    endpointRow->addWidget(copyCurl);
    rpcLayout->addLayout(endpointRow);

    m_logView = new QPlainTextEdit(rpcGroup);
    m_logView->setReadOnly(true);
    m_logView->setMaximumBlockCount(500);
    m_logView->setFont(monospaceFont());
    m_logView->setPlaceholderText(tr("Request log"));
    rpcLayout->addWidget(m_logView, 1);

    detailLayout->addWidget(rpcGroup, 1);

    splitter->addWidget(detailPanel);
    splitter->setStretchFactor(0, 1);
    splitter->setStretchFactor(1, 2);

    outer->addWidget(splitter, 1);
    setCentralWidget(central);
    statusBar()->showMessage(tr("Ready"));
    resize(1040, 660);
}

void MainWindow::buildMenus()
{
    QMenu *fileMenu = menuBar()->addMenu(tr("&File"));

    auto *chooseAction = fileMenu->addAction(tr("Set &Working Directory…"));
    chooseAction->setShortcut(QKeySequence::Open);
    connect(chooseAction, &QAction::triggered, this, &MainWindow::chooseWorkingDirectory);

    m_newAction = fileMenu->addAction(tr("&New Wallet…"));
    m_newAction->setShortcut(QKeySequence::New);
    connect(m_newAction, &QAction::triggered, this, &MainWindow::createWallet);

    m_importAction = fileMenu->addAction(tr("&Import Mnemonic…"));
    m_importAction->setShortcut(QKeySequence(Qt::CTRL | Qt::SHIFT | Qt::Key_I));
    connect(m_importAction, &QAction::triggered, this, &MainWindow::importWallet);

    fileMenu->addSeparator();
    auto *quitAction = fileMenu->addAction(tr("&Quit"));
    quitAction->setShortcut(QKeySequence::Quit);
    quitAction->setMenuRole(QAction::QuitRole);
    connect(quitAction, &QAction::triggered, this, &QWidget::close);

    QMenu *walletMenu = menuBar()->addMenu(tr("&Wallet"));
    m_openAction = walletMenu->addAction(tr("&Open (decrypt)"));
    connect(m_openAction, &QAction::triggered, this, &MainWindow::openSelectedWallet);

    m_closeAction = walletMenu->addAction(tr("&Close"));
    connect(m_closeAction, &QAction::triggered, this, &MainWindow::closeSelectedWallet);

    m_closeAllAction = walletMenu->addAction(tr("Close &All"));
    connect(m_closeAllAction, &QAction::triggered, this, &MainWindow::closeAllWallets);

    QMenu *helpMenu = menuBar()->addMenu(tr("&Help"));
    auto *aboutAction = helpMenu->addAction(tr("&About"));
    aboutAction->setMenuRole(QAction::AboutRole);
    connect(aboutAction, &QAction::triggered, this, [this] {
        QMessageBox::about(
            this,
            tr("About AVXTO Wallet Manager"),
            tr("<h3>AVXTO Wallet Manager %1</h3>"
               "<p>Generates 24-word BIP-39 mnemonics and stores each one as a single "
               "GPG-encrypted <code>.bin</code> file.</p>"
               "<p>Unlocked wallets are held in memory as AES-256-GCM ciphertext under a "
               "per-session password, and can be read back over a loopback-only "
               "JSON-RPC endpoint.</p>"
               "<p>Qt %2 &middot; %3</p>")
                .arg(QString::fromLatin1(AVXTO_VERSION), QString::fromLatin1(qVersion()), m_gpg.version()));
    });
}

void MainWindow::restoreSettings()
{
    QSettings settings;
    if (const QByteArray geometry = settings.value(QLatin1String(kSettingsGeometry)).toByteArray();
        !geometry.isEmpty()) {
        restoreGeometry(geometry);
    }
    if (const QByteArray state = settings.value(QLatin1String(kSettingsState)).toByteArray();
        !state.isEmpty()) {
        restoreState(state);
    }

    const QString saved = settings.value(QLatin1String(kSettingsWorkingDirectory)).toString();
    if (!saved.isEmpty() && QDir(saved).exists())
        setWorkingDirectory(saved, false);
}

void MainWindow::closeEvent(QCloseEvent *event)
{
    QSettings settings;
    settings.setValue(QLatin1String(kSettingsGeometry), saveGeometry());
    settings.setValue(QLatin1String(kSettingsState), saveState());

    // Sessions hold plaintext-equivalent material; drop them explicitly rather
    // than relying on process teardown.
    m_registry.clear();
    m_rpc->stop();

    QMainWindow::closeEvent(event);
}

// ---------------------------------------------------------------------------
// Working directory
// ---------------------------------------------------------------------------

void MainWindow::chooseWorkingDirectory()
{
    const QString start = m_workingDirectory.isEmpty()
        ? QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation)
        : m_workingDirectory;

    const QString chosen = QFileDialog::getExistingDirectory(
        this, tr("Select wallet working directory"), start,
        QFileDialog::ShowDirsOnly | QFileDialog::DontResolveSymlinks);

    if (!chosen.isEmpty())
        setWorkingDirectory(chosen);
}

void MainWindow::setWorkingDirectory(const QString &path, bool persist)
{
    if (!m_watcher->directories().isEmpty())
        m_watcher->removePaths(m_watcher->directories());

    m_workingDirectory = QDir(path).absolutePath();
    m_directoryEdit->setText(QDir::toNativeSeparators(m_workingDirectory));

    if (QDir(m_workingDirectory).exists())
        m_watcher->addPath(m_workingDirectory);

    if (persist) {
        QSettings settings;
        settings.setValue(QLatin1String(kSettingsWorkingDirectory), m_workingDirectory);
    }

    appendLog(tr("Working directory set to %1").arg(m_workingDirectory));
    refreshWalletList();
    updateActions();
}

void MainWindow::refreshWalletList()
{
    const QString previous = selectedFileName();

    // Cheap to recompute and guards against a stale entry if a .bin was
    // replaced (re-created under the same name) since the last refresh.
    m_recipientCache.clear();

    m_walletList->clear();
    if (m_workingDirectory.isEmpty()) {
        updateActions();
        return;
    }

    QDir directory(m_workingDirectory);
    const QStringList files =
        directory.entryList({QStringLiteral("*.bin")}, QDir::Files | QDir::Readable, QDir::Name);

    for (const QString &fileName : files) {
        const QString absolute = directory.absoluteFilePath(fileName);
        const bool unlocked = static_cast<bool>(m_registry.find(absolute));

        auto *item = new QListWidgetItem(unlocked ? QStringLiteral("● %1").arg(fileName)
                                                  : QStringLiteral("○ %1").arg(fileName));
        item->setData(Qt::UserRole, absolute);
        item->setData(Qt::UserRole + 1, fileName);
        item->setToolTip(unlocked ? tr("%1 — unlocked in this session").arg(absolute)
                                  : tr("%1 — locked").arg(absolute));
        item->setFont(monospaceFont());
        m_walletList->addItem(item);

        if (fileName == previous)
            m_walletList->setCurrentItem(item);
    }

    statusBar()->showMessage(tr("%n wallet file(s) in %1", "", static_cast<int>(files.size()))
                                 .arg(QDir::toNativeSeparators(m_workingDirectory)));
    updateActions();
}

// ---------------------------------------------------------------------------
// Wallet operations
// ---------------------------------------------------------------------------

void MainWindow::createWallet()
{
    addWallet(NewWalletDialog::Mode::Generate);
}

void MainWindow::importWallet()
{
    addWallet(NewWalletDialog::Mode::Import);
}

void MainWindow::addWallet(NewWalletDialog::Mode mode)
{
    const bool importing = mode == NewWalletDialog::Mode::Import;

    if (m_workingDirectory.isEmpty()) {
        showError(tr("No working directory"),
                  importing ? tr("Choose a working directory before importing a mnemonic.")
                            : tr("Choose a working directory before creating a wallet."));
        return;
    }
    if (!m_gpg.isAvailable()) {
        showError(tr("GPG not available"),
                  tr("gpg was not found on this system. Install GnuPG and restart."));
        return;
    }

    NewWalletDialog dialog(&m_gpg, m_workingDirectory, mode, this);
    if (dialog.exec() != QDialog::Accepted)
        return;

    const QString name = dialog.walletName();
    const QString recipient = dialog.recipientFingerprint();
    const QString filePath = QDir(m_workingDirectory).filePath(name + QStringLiteral(".bin"));

    try {
        SecureBytes mnemonic = importing ? dialog.mnemonic() : Bip39::generateMnemonic();
        const SecureBytes payload = WalletFile::serialise(mnemonic);
        mnemonic.reset();

        // The dialog's copy is no longer needed once it is in the payload.
        if (importing)
            dialog.clearMnemonic();

        QString error;
        if (!m_gpg.encryptToFile(payload, recipient, filePath, &error)) {
            showError(importing ? tr("Could not import mnemonic") : tr("Could not create wallet"),
                      error);
            return;
        }

        appendLog((importing ? tr("Imported mnemonic as %1.bin, encrypted to %2")
                             : tr("Created %1.bin encrypted to %2"))
                      .arg(name, recipient.right(16)));

        // Open the new wallet straight away so the user gets a session
        // password without a round trip through gpg and pinentry.
        WalletFile::Contents contents;
        if (WalletFile::parse(payload, &contents, &error)) {
            auto session = std::make_shared<WalletSession>(
                name + QStringLiteral(".bin"), filePath, contents.mnemonic, contents.wordCount);
            m_registry.insert(session);
        }

        refreshWalletList();

        QMessageBox::information(
            this,
            importing ? tr("Mnemonic imported") : tr("Wallet created"),
            tr("<p><b>%1.bin</b> was written to the working directory and encrypted to "
               "GPG key <code>%2</code>.</p>"
               "<p>It is open in this session; its session password is shown in the "
               "Session password box.</p>"
               "<p>The mnemonic is not displayed anywhere in this window. Read it back "
               "over the JSON-RPC endpoint, or with "
               "<code>gpg --decrypt %1.bin</code>.</p>")
                .arg(name, recipient.right(16)));
    } catch (const SessionCrypto::CryptoError &error) {
        showError(tr("Cryptographic failure"), error.message());
    } catch (const std::exception &error) {
        showError(importing ? tr("Could not import mnemonic") : tr("Could not create wallet"),
                  QString::fromUtf8(error.what()));
    }
}

void MainWindow::openSelectedWallet()
{
    const QString filePath = selectedFilePath();
    const QString fileName = selectedFileName();
    if (filePath.isEmpty())
        return;

    if (m_activeDecrypt) {
        statusBar()->showMessage(tr("A decryption is already in progress."), 4000);
        return;
    }

    appendLog(tr("Decrypting %1 with gpg…").arg(fileName));

    auto *progress = new QProgressDialog(
        tr("Decrypting %1…\n\nYour GPG agent may ask for the key passphrase.").arg(fileName),
        tr("Cancel"), 0, 0, this);
    progress->setWindowModality(Qt::WindowModal);
    progress->setMinimumDuration(0);
    progress->setAutoClose(false);
    progress->setAutoReset(false);
    progress->show();

    m_activeDecrypt = m_gpg.decryptFile(
        filePath,
        [this, filePath, fileName, progress](GpgManager::DecryptResult result) {
            m_activeDecrypt = nullptr;
            progress->close();
            progress->deleteLater();

            // Re-enable the buttons on every path out of here. A successful
            // open also refreshes them via SessionRegistry::changed, but a
            // failed or cancelled one emits nothing.
            updateActions();

            if (!result.ok) {
                if (result.cancelled) {
                    appendLog(tr("Decryption of %1 cancelled.").arg(fileName));
                    return;
                }
                appendLog(tr("Failed to decrypt %1.").arg(fileName));
                showError(tr("Could not open wallet"), result.error);
                return;
            }

            WalletFile::Contents contents;
            QString error;
            if (!WalletFile::parse(result.plaintext, &contents, &error)) {
                appendLog(tr("%1 decrypted but is not a wallet file.").arg(fileName));
                showError(tr("Not a wallet file"),
                          tr("%1 was decrypted successfully but does not contain a mnemonic.\n\n%2")
                              .arg(fileName, error));
                return;
            }
            result.plaintext.reset();

            try {
                // From here the mnemonic exists only as AES-256-GCM ciphertext.
                auto session = std::make_shared<WalletSession>(
                    fileName, filePath, contents.mnemonic, contents.wordCount);
                contents.mnemonic.reset();
                m_registry.insert(session);

                appendLog(tr("Opened %1 (%2 words, checksum %3). New session password issued.")
                              .arg(fileName)
                              .arg(contents.wordCount)
                              .arg(contents.checksumValid ? tr("valid") : tr("INVALID")));

                if (!contents.checksumValid) {
                    QMessageBox::warning(
                        this,
                        tr("Checksum mismatch"),
                        tr("The mnemonic in %1 does not have a valid BIP-39 checksum. "
                           "The wallet has been opened anyway, but it may be corrupt or may "
                           "come from a non-standard tool.")
                            .arg(fileName));
                }
            } catch (const SessionCrypto::CryptoError &cryptoError) {
                showError(tr("Cryptographic failure"), cryptoError.message());
            }
        },
        this);

    connect(progress, &QProgressDialog::canceled, this, [this] {
        if (m_activeDecrypt)
            m_activeDecrypt->cancel();
    });

    updateActions();
}

void MainWindow::closeSelectedWallet()
{
    const QString filePath = selectedFilePath();
    if (filePath.isEmpty())
        return;

    if (m_registry.remove(filePath)) {
        appendLog(tr("Closed %1. Its session password no longer works.").arg(selectedFileName()));
        m_revealButton->setChecked(false);
    }
}

void MainWindow::closeAllWallets()
{
    if (m_registry.count() == 0)
        return;
    m_registry.clear();
    m_revealButton->setChecked(false);
    appendLog(tr("All wallets closed; every session password has been revoked."));
}

// ---------------------------------------------------------------------------
// Details pane
// ---------------------------------------------------------------------------

void MainWindow::updateDetails()
{
    const QString filePath = selectedFilePath();
    const WalletSessionPtr session = filePath.isEmpty() ? WalletSessionPtr{}
                                                        : m_registry.find(filePath);

    if (filePath.isEmpty()) {
        m_fileNameValue->setText(placeholder());
        m_encryptedToValue->setText(placeholder());
        m_statusValue->setText(tr("no wallet selected"));
    } else {
        m_fileNameValue->setText(selectedFileName());
        // Reading the recipient is a packet-header lookup, not a decrypt —
        // it works on a still-locked wallet just as well as an open one.
        m_encryptedToValue->setText(recipientFor(filePath).displayText());
        m_statusValue->setText(session ? tr("unlocked in this session")
                                       : tr("locked — double-click to decrypt"));
    }

    if (session) {
        m_firstWordValue->setText(session->firstWord());
        m_lastWordValue->setText(session->lastWord());
        m_wordCountValue->setText(QString::number(session->wordCount()));
        m_openedAtValue->setText(session->openedAt().toString(Qt::ISODate));
        m_passwordEdit->setText(session->sessionPassword().toQString());
    } else {
        m_firstWordValue->setText(placeholder());
        m_lastWordValue->setText(placeholder());
        m_wordCountValue->setText(placeholder());
        m_openedAtValue->setText(placeholder());
        m_passwordEdit->clear();
    }

    const bool hasSession = static_cast<bool>(session);
    m_passwordEdit->setEnabled(hasSession);
    m_revealButton->setEnabled(hasSession);
    m_copyPasswordButton->setEnabled(hasSession);
    if (!hasSession)
        m_revealButton->setChecked(false);
}

void MainWindow::updateActions()
{
    const bool haveDirectory = !m_workingDirectory.isEmpty();
    const bool haveSelection = !selectedFilePath().isEmpty();
    const bool haveSession = haveSelection && static_cast<bool>(m_registry.find(selectedFilePath()));
    const bool gpgReady = m_gpg.isAvailable();
    const bool busy = m_activeDecrypt != nullptr;

    m_newButton->setEnabled(haveDirectory && gpgReady && !busy);
    m_newAction->setEnabled(haveDirectory && gpgReady && !busy);
    m_importButton->setEnabled(haveDirectory && gpgReady && !busy);
    m_importAction->setEnabled(haveDirectory && gpgReady && !busy);

    m_openButton->setEnabled(haveSelection && gpgReady && !busy);
    m_openAction->setEnabled(haveSelection && gpgReady && !busy);

    m_closeButton->setEnabled(haveSession);
    m_closeAction->setEnabled(haveSession);
    m_closeAllAction->setEnabled(m_registry.count() > 0);
}

void MainWindow::copySessionPassword()
{
    const WalletSessionPtr session = m_registry.find(selectedFilePath());
    if (!session)
        return;

    QString password = session->sessionPassword().toQString();
    QGuiApplication::clipboard()->setText(password);
    wipe(password);

    statusBar()->showMessage(tr("Session password copied to the clipboard."), 5000);
}

void MainWindow::copyRpcEndpoint()
{
    if (!m_rpc->isListening()) {
        statusBar()->showMessage(tr("The RPC endpoint is not listening."), 4000);
        return;
    }

    QGuiApplication::clipboard()->setText(m_rpc->endpoint());
    statusBar()->showMessage(tr("Endpoint URL copied to the clipboard."), 5000);
}

void MainWindow::copyRpcExample()
{
    if (!m_rpc->isListening()) {
        statusBar()->showMessage(tr("The RPC endpoint is not listening."), 4000);
        return;
    }

    const WalletSessionPtr session = m_registry.find(selectedFilePath());
    QString password = session ? session->sessionPassword().toQString()
                               : QStringLiteral("<session-password>");

    const QString command =
        QStringLiteral(
            "curl -s -X POST %1 \\\n"
            "  -H 'Content-Type: application/json' \\\n"
            "  -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"read\","
            "\"params\":{\"password\":\"%2\"}}'")
            .arg(m_rpc->endpoint(), password);

    QGuiApplication::clipboard()->setText(command);
    wipe(password);

    statusBar()->showMessage(tr("curl example copied to the clipboard."), 5000);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

QString MainWindow::selectedFilePath() const
{
    const QListWidgetItem *item = m_walletList->currentItem();
    return item && item->isSelected() ? item->data(Qt::UserRole).toString() : QString();
}

QString MainWindow::selectedFileName() const
{
    const QListWidgetItem *item = m_walletList->currentItem();
    return item && item->isSelected() ? item->data(Qt::UserRole + 1).toString() : QString();
}

const GpgRecipient &MainWindow::recipientFor(const QString &filePath)
{
    auto it = m_recipientCache.find(filePath);
    if (it == m_recipientCache.end())
        it = m_recipientCache.insert(filePath, m_gpg.identifyRecipient(filePath));
    return it.value();
}

void MainWindow::appendLog(const QString &line)
{
    m_logView->appendPlainText(line);
}

void MainWindow::showError(const QString &title, const QString &message)
{
    QMessageBox::critical(this, title, message);
}
