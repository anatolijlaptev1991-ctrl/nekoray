#include "HappLink.hpp"

#include <QCoreApplication>
#include <QJsonDocument>
#include <QJsonObject>
#include <QProcess>

#ifdef Q_OS_WIN
#define NKR_CORE_BINARY "nekobox_core.exe"
#else
#define NKR_CORE_BINARY "nekobox_core"
#endif

namespace NekoGui_Happ {

    bool IsHappLink(const QString &s) {
        return s.trimmed().startsWith("happ://crypt", Qt::CaseInsensitive);
    }

    QString HappDecryptLink(const QString &link, QString *err) {
        if (err != nullptr) err->clear();

        if (!IsHappLink(link)) {
            if (err != nullptr) *err = QObject::tr("Not an encrypted Happ link");
            return "";
        }

        QProcess process;
        process.setProgram(QCoreApplication::applicationDirPath() + "/" + NKR_CORE_BINARY);
        process.setArguments({"happ-decrypt", link.trimmed()});
        process.setProcessChannelMode(QProcess::SeparateChannels);
        process.start();
        if (!process.waitForStarted(3000) || !process.waitForFinished(10000)) {
            process.kill();
            process.waitForFinished(1000);
            if (err != nullptr) *err = QObject::tr("Could not run the decryptor (nekobox_core)");
            return "";
        }

        auto reply = QJsonDocument::fromJson(process.readAllStandardOutput());
        if (!reply.isObject()) {
            if (err != nullptr) *err = QObject::tr("Unexpected decryptor output");
            return "";
        }
        auto obj = reply.object();
        if (!obj.value("ok").toBool()) {
            auto error = obj.value("error").toString();
            if (err != nullptr) *err = error.isEmpty() ? QObject::tr("Decryption failed") : error;
            return "";
        }
        auto result = obj.value("result").toString();
        if (result.isEmpty()) {
            if (err != nullptr) *err = QObject::tr("Decryption returned an empty result");
            return "";
        }
        return result;
    }

} // namespace NekoGui_Happ
