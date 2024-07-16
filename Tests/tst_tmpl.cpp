/*
 * © 2023
 * Author: Akhat T. Kuangaliyev
 * Company: Jupiter Soft
 */
#include <QCoreApplication>
#include <QtTest>

// add necessary includes here

class Templ : public QObject {
    Q_OBJECT

  public:
    Templ() {}
    ~Templ() {}

  private slots:
    void initTestCase() {}
    void cleanupTestCase() {}
    void test_case1() {}
};


QTEST_MAIN(Templ)

#include "tst_templ.moc"
