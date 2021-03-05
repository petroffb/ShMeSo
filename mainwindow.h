#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QtWidgets>
#include <iostream>
#include <boost/array.hpp>
#include <boost/asio.hpp>
using boost::asio::ip::tcp;
#include <string>
#include <QDebug>
#include <QObject>
#include <libssh/libssh.h>
#include "enum.h"

class WgtForTab;


class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();


private:
    QSplitter* wgtCentr;          // Центральный виджет
    QWidget* wgtCommonData;     // Левый виджет с общей информацией
    QVBoxLayout* lot_common_data; // Слой виджета QWidget* wgtCommonData
    QBoxLayout* lot_ip_type;
    QTabWidget* wgtTabs;        // Виджет вкладок
    QTreeWidget* tree_wgt;              //Вложенный список серверов
    QLabel* lbl_ip_serv_info;       // Инфо поле ввода ip адреса сервера
    QLineEdit* txt_ip_serv;         //  Поле ввода адреса сервера для подключения
    QLabel* lbl_login_serv;         // Инфо поле ввода логина сервера
    QLineEdit* txt_login_serv;      // Поле ввода логина на сервер для подключения
    QLabel* lbl_pass_serv;          // Инфо поле ввода пароля сервера
    QLineEdit* txt_pass_serv;        // Поле ввода пароля для подключения
    QPushButton* btn_connect_to_serv;   // Кнопка подключения к серверу по указанному в поле адресу
    QComboBox* cmb_srv_type;          // Выпадающий список типов серверов


public slots:
    void NewTab();
    void onTabCloseRequest(int);


};
class WgtCPUAffinity;
class WgtTextEdit;



// Виджет для содержимого вкладки. Будет помещаться в контейнер по кол-ву вкладок

class WgtForTab : public QWidget {
    Q_OBJECT

public:
    WgtForTab(Type_Server, QString, QString, QString, QWidget *prnt = nullptr);
    std::string strAddr;
    ~WgtForTab();

    int Verify_knownhost (ssh_session);
    int Remote_act(Orders, bool);       // bool - true действие get, иначе set
    void StopSSHSess();
    QMap<Type_Server, QString> sign_types;      // Строковые сигнатуры из hostname для определения типа сервера
    Type_Server DefineTypeSrv(QString);

// ====> Команды (Instructions) и результаты ====
    std::list<std::string> list_instructions;
    QMap<Orders, QString> instructions_and_results;
//    QString config_path = "/home/user/programs.config/";
    QString config_path = "/home/user/programs.config_test/"; // For tests
    QString instruction_ls_conf = "ls " + config_path;
    QString instruction_get_cz_1 = "cat " + config_path + "cenzor/cenzor.1.ini";
    QString instruction_get_cz_2 = "cat " + config_path + "cenzor/cenzor.2.ini";
    QString instruction_get_dragonet = "cat " + config_path + "dragonet/dragonet.xml";
    QString instruction_get_hostname = "hostname";
    QString instruction_get_cpus_count = "nproc --all";
    QString instruction_get_nodes_count = "lscpu | grep \"NUMA node(s)\" | sed 's/[^0-9]//g'";
    QString instruction_get_ipmimon = "cat " + config_path + "ipmimon/ipmimon.xml";
    QString instruction_get_replicator = "cat " + config_path + "replicator/replicator.xml";
    QString instruction_get_sorm = "cat " + config_path + "sorm/sorm.xml";
    QString instruction_get_xmanager = "cat " + config_path + "xmanager/xmanager.xml";
    QStringList instruction_set_aff_cz_test = {"", ""};

// <==== Команды (Instructions) и результаты ====


    ssh_session ssh_sess;
    Type_Server srv_type;               // Тип сервера
    QString srv_type_str;
    QString host_address;
    QString login;
    QString password;

public slots:
    void connect_check();
    void GetContent();
    void Connect_via_ssh(QString, QString, QString); // Подключение по ssh
    void OnSaveAffinity();


private:
    QBoxLayout* centralLayout;
    QGridLayout* lot_cfgs;                // Слой текстовых полей файлов конфигурации
    QBoxLayout* lot_lbl;                  // Слой информационной строки
    QBoxLayout* lot_srv_info;             // Слой информационных полей о сервере: ip, hostname
    QBoxLayout* lot_func_btns;           // Слой функциональных кнопок (справа)
    QLabel* lbl_type_server;              // Инф. предположительный тип сервара (съём, Р, МО и т.д.)
    QLineEdit* txt_type_server;
    QLabel* lbl_hostname;                   // Hostname
    QLineEdit* txt_hostname;
    WgtCPUAffinity* affinity;
    QPushButton* btn_getContent;             // Получить содержимое файлов-конфигов
    QPushButton* btn_connect;                 // Test connect
    QPushButton* btn_save_affinity;               // Сохранить изменения
// ==== Manager ====
    WgtTextEdit* manager;
    WgtTextEdit* ipmimon;


};

// Виджеты для настройки процессорной привязки

class CPUCoreButton : public QPushButton {
    Q_OBJECT

public:
    CPUCoreButton(int core_num, QWidget *prnt = nullptr);

    bool inUse;
    QPalette pal;
    Statement statement;

    bool getState();
    void setState(Statement st);
signals:
    void chpock();
public slots:
    void OnClicked();
};

// Информационное окно

class InfoMessage : public QWidget {
    Q_OBJECT

public:
    InfoMessage(QString message, QWidget *prnt = nullptr);
    QLabel* lbl_message;
    QPushButton* btn_ok;
    QVBoxLayout* lot;
};

class WgtCPUAffinity : public QWidget {
    Q_OBJECT

public:
    WgtCPUAffinity(const QMap<Orders, QString> &, QWidget *prnt = nullptr);
    void SetCPUCount(int);
    void SetCoresCount(int);
    QString GetAffinity();
    void SetChecks(QString);        // Установка значений чекбоксов и lbl_CPUS_count_HEX
    QStringList GetModuleName(Orders);
    QMap<QString, QString> GetMapOriginal();
    QMap<QString, QString> GetMapModified();

    // ====> Поле чекбоксов\кнопок
    QVector<QCheckBox*> vct_check_box;
    QVector <CPUCoreButton*> vct_buttons;
    QVector<QHBoxLayout*> vct_hlt;
    QLabel* lbl_CPUS_count_HEX;
    // <==== Поле чекбоксов\кнопок


private:
// ==== CPU Affinity ====

    QBoxLayout* centralLayout;  // Основной слой
    QHBoxLayout* hlt;           // Горизонтальный слой для списка модулей и поля выбора ядер

    QStringList list_modules; // Список модулей для которых настраивается привязка
    QTreeWidgetItem* item_module = nullptr;
    QTreeWidget* wgt_list_modules;              // Виюшка для модулей
    QGroupBox* group_cores;


    int cpus_count;
    int cores_count;
    // Контейнеры хранения пар ключ(текстовое описание)=значение из конфигов
    QMap<QString, QString> modules_affinity;
    QMap<QString, QString> modules_affinity_original;
    QMap<QString, QString> modules_affinity_modified;

    /* !ВАЖНО! сделать проверку на сравнение считанного значения привязки из конфига и общего числа ядер
     на текущем сервере */



public slots:
    void List_modules_row_changed(QTreeWidgetItem*, QTreeWidgetItem*);  // Ловим выбранный элемент в древе модулей
    void On_CheckBox_Clicked();                         // Расчет привязки по состояниям чекбоксов
    void OnCPUButtonChpock();
};

// Виджет для текста конфигов

class WgtTextEdit : public QWidget {
    Q_OBJECT

public:
    WgtTextEdit(QString, QWidget* prnt = nullptr);
    QLabel* header;
    QTextEdit* txt;
    QBoxLayout* lot_cntrl;
    void SetText(QString);

};

// ==== WgtCenzorConfig ====

class WgtCenzorConfig : public QWidget {
    Q_OBJECT

public:
    WgtCenzorConfig(QWidget* prnt = nullptr);
private:
    // ====> Layouts ====
    QGridLayout* lot_main;       // Основной слой
    // <==== Layouts ====
    QMap<QString, QString>* map_config; // Контейнер пар из конфига ("ключ=значение")
    // ====> Labels & LineEdit ====
    // <==== Labels & LineEdit ====
    QGroupBox* gp_box;
};

// ==== WgtWrhgConfig ====

class WgtWrhgConfig : public QWidget {
    Q_OBJECT

public:
    WgtWrhgConfig(QWidget* prnt = nullptr);
};
#endif // MAINWINDOW_H
