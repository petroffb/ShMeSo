#include "mainwindow.h"

#include <QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    MainWindow w;
    w.resize(1400, 800);
    w.show();
//    QString str = "sed -i \"s/^%1/c %1=0x000ffff\" ";
//    qDebug() << "QT " << str;
//    std::cout << "c++ " << str.toStdString() << std::endl;

    return a.exec();
}
