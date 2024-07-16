/*
 * © 2023
 * Author: Akhat T. Kuangaliyev
 * Company: Jupiter Soft
 */
#include <QCoreApplication>
#include <QtTest>

#include <secp256k1s.h>
#include <sha2.h>

// add necessary includes here
namespace Sekura::Crypto {

    class TestSecp256k1 : public QObject {
        Q_OBJECT

      public:
        TestSecp256k1() {}
        ~TestSecp256k1() {}

      private slots:
        void initTestCase() {}
        void cleanupTestCase() {}
        void test_case1() {
            QByteArray privkey;
            QRandomGenerator g = QRandomGenerator::securelySeeded();
            do {
                Crypt::Sha256 sha;
                QString str = QString("%1").arg(g.generate64(), 0, 16);
                sha.addData(str.toUtf8());
                sha.addData(QDateTime::currentDateTime().toString().toUtf8());
                sha.addData("test");
                privkey = sha.result();
            } while (!Crypt::Secp256k1::privkeyvalid(privkey));
            QByteArray pubkey = Crypt::Secp256k1::pubkey(privkey);
            QByteArray compk = Crypt::Secp256k1::compress(pubkey);
            QByteArray ucmpk = Crypt::Secp256k1::uncompress(compk);
            QCOMPARE(pubkey, ucmpk);

            Crypt::Sha256 sha;
            sha.addData("data");
            sha.addData("val");
            sha.addData("order");
            QByteArray res = sha.result();
            QByteArray sign = Crypt::Secp256k1::sign(privkey, res);
            qDebug() << sign.size();
            qDebug() << sign.toBase64();
        }
    };

} // namespace Sekura::Crypto

QTEST_MAIN(Sekura::Crypto::TestSecp256k1)

#include "tst_secp256k1.moc"
