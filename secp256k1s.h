/*
 * © 2022
 * Author: Akhat T. Kuangaliyev
 * Company: Jupiter Soft
 */
#ifndef QSECP256K1ENCRYPTION_H
#define QSECP256K1ENCRYPTION_H

#include <QByteArray>
#include <QObject>

namespace Sekura::Crypt {

    class Secp256k1 : public QObject {
        Q_OBJECT
      public:
        explicit Secp256k1(QObject *parent = nullptr);

        static QByteArray pubkey(const QByteArray &key);
        static QByteArray sign(const QByteArray &key, const QByteArray &hash);
        static bool verify(const QByteArray &signture, const QByteArray &pubkey,
                           const QByteArray &hash);
        static bool privkeyvalid(const QByteArray &key);
        static QByteArray compress(const QByteArray &pubkey);
        static QByteArray uncompress(const QByteArray &pubkey);

      signals:

      private:
    };

} // namespace Sekura::Crypt

#endif // QSECP256K1ENCRYPTION_H
