#include "dialog_happ_decrypt.h"

#include "main/HappLink.hpp"
#include "sub/GroupUpdater.hpp"

#include <QApplication>
#include <QClipboard>
#include <QHBoxLayout>
#include <QLabel>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QTimer>
#include <QVBoxLayout>

DialogHappDecrypt::DialogHappDecrypt(QWidget *parent) : QDialog(parent) {
    setWindowTitle(tr("Decrypt Happ link"));
    setWindowFlag(Qt::WindowContextHelpButtonHint, false);
    setMinimumSize(520, 360);

    auto *layout = new QVBoxLayout(this);

    layout->addWidget(new QLabel(tr("Paste an encrypted Happ link (happ://crypt...):"), this));
    inputEdit = new QPlainTextEdit(this);
    inputEdit->setPlaceholderText("happ://crypt5/...");
    inputEdit->setMaximumHeight(90);
    layout->addWidget(inputEdit);

    auto *decryptRow = new QHBoxLayout();
    btnDecrypt = new QPushButton(tr("Decrypt"), this);
    btnDecrypt->setDefault(true);
    decryptRow->addWidget(btnDecrypt);
    decryptRow->addStretch();
    layout->addLayout(decryptRow);

    layout->addWidget(new QLabel(tr("Decrypted result:"), this));
    resultEdit = new QPlainTextEdit(this);
    resultEdit->setReadOnly(true);
    resultEdit->setMaximumHeight(110);
    resultEdit->setPlaceholderText(tr("The decrypted link will appear here"));
    layout->addWidget(resultEdit);

    statusLabel = new QLabel("", this);
    statusLabel->setWordWrap(true);
    layout->addWidget(statusLabel);

    auto *actionRow = new QHBoxLayout();
    btnAdd = new QPushButton(tr("Add to NekoBox"), this);
    btnCopy = new QPushButton(tr("Copy result"), this);
    btnClose = new QPushButton(tr("Close"), this);
    actionRow->addWidget(btnAdd);
    actionRow->addWidget(btnCopy);
    actionRow->addStretch();
    actionRow->addWidget(btnClose);
    layout->addLayout(actionRow);

    btnAdd->setEnabled(false);
    btnCopy->setEnabled(false);

    connect(btnDecrypt, &QPushButton::clicked, this, &DialogHappDecrypt::onDecryptClicked);
    connect(btnAdd, &QPushButton::clicked, this, &DialogHappDecrypt::onAddClicked);
    connect(btnCopy, &QPushButton::clicked, this, &DialogHappDecrypt::onCopyClicked);
    connect(btnClose, &QPushButton::clicked, this, &QDialog::accept);
}

void DialogHappDecrypt::onDecryptClicked() {
    auto link = inputEdit->toPlainText().trimmed();
    if (link.isEmpty()) {
        inputEdit->setFocus();
        return;
    }

    btnDecrypt->setEnabled(false);
    setCursor(Qt::WaitCursor);
    QApplication::processEvents(QEventLoop::ExcludeUserInputEvents);

    QString err;
    auto result = NekoGui_Happ::HappDecryptLink(link, &err);

    unsetCursor();
    btnDecrypt->setEnabled(true);

    if (result.isEmpty()) {
        statusLabel->clear();
        QMessageBox::warning(this, tr("Decrypt Happ link"), err.isEmpty() ? tr("Decryption failed") : err);
        return;
    }
    setResult(result);
}

void DialogHappDecrypt::setResult(const QString &result) {
    resultEdit->setPlainText(result);
    bool isUrl = result.startsWith("http://") || result.startsWith("https://");
    statusLabel->setText(isUrl ? tr("Looks like a subscription URL. \"Add to NekoBox\" will offer to create a subscription.")
                               : tr("Looks like one or more proxy links."));
    btnAdd->setEnabled(true);
    btnCopy->setEnabled(true);
}

void DialogHappDecrypt::onAddClicked() {
    auto result = resultEdit->toPlainText().trimmed();
    if (result.isEmpty()) return;
    NekoGui_sub::groupUpdater->AsyncUpdate(result);
    accept();
}

void DialogHappDecrypt::onCopyClicked() {
    QApplication::clipboard()->setText(resultEdit->toPlainText());
    btnCopy->setText(tr("Copied!"));
    QTimer::singleShot(1500, this, [this] { btnCopy->setText(tr("Copy result")); });
}
