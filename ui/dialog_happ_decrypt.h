#pragma once

#include <QDialog>

class QLabel;
class QPlainTextEdit;
class QPushButton;

class DialogHappDecrypt : public QDialog {
    Q_OBJECT
public:
    explicit DialogHappDecrypt(QWidget *parent = nullptr);

private slots:
    void onDecryptClicked();
    void onAddClicked();
    void onCopyClicked();

private:
    void setResult(const QString &result);

    QPlainTextEdit *inputEdit;
    QPlainTextEdit *resultEdit;
    QLabel *statusLabel;
    QPushButton *btnDecrypt;
    QPushButton *btnAdd;
    QPushButton *btnCopy;
    QPushButton *btnClose;
};
