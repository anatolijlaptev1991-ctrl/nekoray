#pragma once

#include <QString>

namespace NekoGui_Happ {

    // Reports whether the string looks like an encrypted Happ link
    // (happ://crypt .. happ://crypt5).
    bool IsHappLink(const QString &s);

    // Decrypts an encrypted Happ link by running `nekobox_core happ-decrypt`
    // as a short-lived subprocess. Works whether or not the core daemon is
    // running. Returns the decrypted URL/text, or an empty string and sets
    // *err on failure.
    QString HappDecryptLink(const QString &link, QString *err);

} // namespace NekoGui_Happ
