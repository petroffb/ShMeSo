#include "mainwindow.h"

//===== MainWindow =====

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
{
//    setMinimumSize(1500, 700);
    wgtCentr = new QSplitter;
    wgtCommonData = new QWidget(this);
    wgtCommonData->setMinimumWidth(300);
    lot_common_data = new QVBoxLayout;
    lot_ip_type = new QBoxLayout(QBoxLayout::LeftToRight);
    wgtCommonData->setLayout(lot_common_data);
    lbl_ip_serv_info = new QLabel("IP сервера");
    txt_ip_serv = new QLineEdit();
    cmb_srv_type = new QComboBox;
    // ====> Выпадающий список типов серверов, наполнение
    cmb_srv_type->insertItem(0, "UNDEFINITE");
    cmb_srv_type->insertItem(1, "GE");
    cmb_srv_type->insertItem(2, "R");
    cmb_srv_type->insertItem(3, "MO");
    cmb_srv_type->insertItem(4, "IP");
    cmb_srv_type->insertItem(5, "PD");
    cmb_srv_type->insertItem(6, "SMNK 139");
    // <==== Выпадающий список типов серверов, наполнение
    lbl_login_serv = new QLabel("Логин");
    txt_login_serv = new QLineEdit("user");
    lbl_pass_serv = new QLabel("Пароль");
    txt_pass_serv = new QLineEdit("Adid@$");
    btn_connect_to_serv = new QPushButton("Подключиться");
    tree_wgt = new QTreeWidget();
//    tree_wgt->resize(300, 400);
    lot_common_data->addWidget(lbl_ip_serv_info);
    lot_common_data->addLayout(lot_ip_type);
    lot_ip_type->addWidget(txt_ip_serv);
    lot_ip_type->addWidget(cmb_srv_type);
    lot_common_data->addWidget(lbl_login_serv);
    lot_common_data->addWidget(txt_login_serv);
    lot_common_data->addWidget(lbl_pass_serv);
    lot_common_data->addWidget(txt_pass_serv);
    lot_common_data->addWidget(btn_connect_to_serv);
    lot_common_data->addWidget(tree_wgt);
    lot_common_data->addStretch(1);
    wgtTabs = new QTabWidget;
    wgtTabs->setTabsClosable(true);
    wgtCentr->addWidget(wgtCommonData);
    wgtCentr->addWidget(wgtTabs);

    setCentralWidget(wgtCentr);

    //==== TESTING =======

//    wgtTabs->addTab(new WgtForTab("15.0.8.88", wgtTabs), "First tab");

    //====

    connect(btn_connect_to_serv, SIGNAL(clicked()), this, SLOT(NewTab()));
    connect(wgtTabs, SIGNAL(tabCloseRequested(int)), this, SLOT(onTabCloseRequest(int)));

}

MainWindow::~MainWindow()
{
}
//==== SLOTS ====

void MainWindow::NewTab() {
    wgtTabs->addTab(new WgtForTab((Type_Server)cmb_srv_type->currentIndex() ,txt_ip_serv->text(), txt_login_serv->text(),
                                  txt_pass_serv->text(), wgtTabs), txt_ip_serv->text());
    qDebug() << "NewTab DONE";

}

void MainWindow::onTabCloseRequest(int index) {
    wgtTabs->removeTab(index);
}

//===== WgtForTab =====

WgtForTab::WgtForTab(Type_Server type_srv ,QString address, QString log, QString pass, QWidget *prnt) : QWidget(prnt)
{
    srv_type = type_srv;
    switch (srv_type) {
    case UNDEF:
        srv_type_str = "UNDEFINITE";
        break;
    case GE:
        srv_type_str = "GE";
        break;
    case R:
        srv_type_str = "R";
        break;
    case MO:
        srv_type_str = "MO";
        break;
    case IP:
        srv_type_str = "IP";
        break;
    case PD:
        srv_type_str = "PD";
        break;
    case SMNK139:
        srv_type_str = "SMNK 139";
        break;
    }

    host_address = address;
    login = log;
    password = pass;

    Connect_via_ssh(host_address, login, password);
// ==== Читаем характеристики сервера


//    Remote_act() for meta-data;
    Remote_act(GET_HOSTNAME, true);
    Remote_act(GET_NODES_COUNT, true);
    Remote_act(GET_CPUS_COUNT, true);
    Remote_act(GET_CONF_IPMIMON, true);
    Remote_act(GET_CONF_REPLICATOR, true);
    Remote_act(GET_CONF_SORM, true);
    Remote_act(GET_CONF_XMANAGER, true);
    Remote_act(GET_CONF_CZ_1, true);
    Remote_act(GET_CONF_CZ_2, true);
// ==== Информационная строка ====
    lbl_type_server = new QLabel;
    lbl_type_server->resize(100, 40);
    lbl_type_server->setText("Тип сервера");
    txt_type_server = new QLineEdit("UNDEF");
    txt_type_server->setText(srv_type_str);
    txt_type_server->setReadOnly(true);
    lbl_hostname = new QLabel("HostName");
//    lbl_hostname->resize(140, 40);
    txt_hostname = new QLineEdit;
    txt_hostname->setMinimumWidth(250);
    txt_hostname->setReadOnly(true);
    btn_getContent = new QPushButton("Считать конфиги");
    centralLayout = new QBoxLayout(QBoxLayout::TopToBottom);
    lot_lbl = new QBoxLayout(QBoxLayout::LeftToRight);
    lot_srv_info = new QBoxLayout(QBoxLayout::TopToBottom);
    lot_func_btns = new QBoxLayout(QBoxLayout::TopToBottom);
    lot_lbl->addLayout(lot_srv_info);
    lot_srv_info->addWidget(lbl_type_server);
    lot_srv_info->addWidget(txt_type_server);
    lot_srv_info->addWidget(lbl_hostname);
    lot_srv_info->addWidget(txt_hostname);
    lot_srv_info->addStretch(1);
// ====> Widget CPU Affinity ====

    affinity = new WgtCPUAffinity(instructions_and_results, this);
    lot_lbl->addWidget(affinity);
// <==== Widget CPU Affinity ====

    lot_lbl->addStretch(1);
    lot_func_btns->addWidget(btn_getContent);
    btn_connect = new QPushButton("Test ssh");
    lot_func_btns->addWidget(btn_connect);
    btn_save_affinity = new QPushButton("Save");
    lot_func_btns->addWidget(btn_save_affinity);
    lot_func_btns->addStretch(1);
    lot_lbl->addLayout(lot_func_btns);
    centralLayout->addLayout(lot_lbl);

    lot_cfgs = new QGridLayout;
    centralLayout->addLayout(lot_cfgs);
    centralLayout->addStretch(1);
    setLayout(centralLayout);


    txt_hostname->setText(instructions_and_results[GET_HOSTNAME]);
    StopSSHSess();

// ====> Наполнение контейнера сигнатур типов сервера
    sign_types.insert(GE, "GE");
    sign_types.insert(R, "-R-");
    sign_types.insert(MO, "MO-");
    sign_types.insert(IP, "IP");
    sign_types.insert(PD, "PD");
    sign_types.insert(SMNK139, "SMNK-139");
// <==== Наполнение контейнера сигнатур типов сервера
//    srv_type = DefineTypeSrv(instructions_and_results[GET_HOSTNAME]);

    switch (srv_type) {
    {case Type_Server::UNDEF:
        WgtTextEdit* ipmi_mon = new WgtTextEdit("IpmiMon");
        lot_cfgs->addWidget(ipmi_mon, 0, 0, 5, 10);
            break;}
    case Type_Server::GE:
        break;
    case Type_Server::R:
        break;
    {case Type_Server::MO:
        txt_type_server->setText("MO");
        ipmimon = new WgtTextEdit("IpmiMon");
        lot_cfgs->addWidget(ipmimon, 0, 0, 5, 7);
        manager = new WgtTextEdit("Manager");
        lot_cfgs->addWidget(manager, 0, 8, 5, 10);
        break;}
    case Type_Server::IP:
        break;
    case Type_Server::PD:
        break;
    case Type_Server::SMNK139:

        break;
    }
    // ====> Соединение сигналов и слотов
    connect(btn_getContent, SIGNAL(clicked()), SLOT(GetContent()));
    connect(btn_save_affinity, SIGNAL(clicked()), SLOT(OnSaveAffinity()));
    // <==== Соединение сигналов и слотов

}

WgtForTab::~WgtForTab()
{

}

// ==== FUNCTIONS ====
Type_Server WgtForTab::DefineTypeSrv(QString str) {
    Type_Server type = UNDEF;
    foreach (QString tmp_str, sign_types.values()) {
        if(str.contains(tmp_str)) {
            type = sign_types.key(tmp_str);
        }
    }
    return type;
}

int WgtForTab::Verify_knownhost(ssh_session session) {
    int state, hlen;
    unsigned char *hash = nullptr;
    char *hexa;
    char buf[10];

    state = ssh_is_server_known(session);

    hlen = ssh_get_pubkey_hash(session, &hash);
    if (hlen < 0)
    return -1;

    switch (state)
    {
    case SSH_SERVER_KNOWN_OK:
    break; /* ok */

    case SSH_SERVER_KNOWN_CHANGED:
    fprintf(stderr, "Host key for server changed: it is now:\n");
    ssh_print_hexa("Public key hash", hash, hlen);
    fprintf(stderr, "For security reasons, connection will be stopped\n");
    free(hash);
    return -1;

    case SSH_SERVER_FOUND_OTHER:
    fprintf(stderr, "The host key for this server was not found but an other"
    "type of key exists.\n");
    fprintf(stderr, "An attacker might change the default server key to"
    "confuse your client into thinking the key does not exist\n");
    free(hash);
    return -1;

    case SSH_SERVER_FILE_NOT_FOUND:
    fprintf(stderr, "Could not find known host file.\n");
    fprintf(stderr, "If you accept the host key here, the file will be"
    "automatically created.\n");
    /* Возвращение к ситуации SSH_SERVER_NOT_KNOWN(прим. перевод. т.е. сервер неизвестен) */

    BOOST_FALLTHROUGH; case SSH_SERVER_NOT_KNOWN:
    hexa = ssh_get_hexa(hash, hlen);
    fprintf(stderr,"The server is unknown. Do you trust the host key?\n");
    fprintf(stderr, "Public key hash: %s\n", hexa);
    free(hexa);
    if (fgets(buf, sizeof(buf), stdin) == nullptr)
    {
    free(hash);
    return -1;
    }
    if (strncasecmp(buf, "yes", 3) != 0)
    {
    free(hash);
    return -1;
    }
    if (ssh_write_knownhost(session) < 0)
    {
    fprintf(stderr, "Error %s\n", strerror(errno));
    free(hash);
    return -1;
    }
    break;

    case SSH_SERVER_ERROR:
    fprintf(stderr, "Error %s", ssh_get_error(session));
    free(hash);
    return -1;
    }
    free(hash);
    return 0;
}

int WgtForTab::Remote_act(Orders order, bool gs) {
    ssh_channel channel;
    int rc;
    char buffer[10000] = {0};
    std::string tst_str;
    tst_str.clear();
    int nbytes;
//    std::cout << buffer << std::endl;

    channel = ssh_channel_new(ssh_sess);
    if (channel == nullptr) return SSH_ERROR;

    rc = ssh_channel_open_session(channel);
    if (rc != SSH_OK)
    {
    ssh_channel_free(channel);
    return rc;
    }
    switch (order) {
    case GET_HOSTNAME:
        rc = ssh_channel_request_exec(channel, instruction_get_hostname.toLocal8Bit().data());
        break;
    case GET_NODES_COUNT:
        rc = ssh_channel_request_exec(channel, instruction_get_nodes_count.toLocal8Bit().data());
        break;
    case GET_CPUS_COUNT:
        rc = ssh_channel_request_exec(channel, instruction_get_cpus_count.toLocal8Bit().data());
        break;
    case GET_CONF_IPMIMON:
        rc = ssh_channel_request_exec(channel, instruction_get_ipmimon.toLocal8Bit().data());
        break;
    case GET_CONF_REPLICATOR:
        rc = ssh_channel_request_exec(channel, instruction_get_replicator.toLocal8Bit().data());
        break;
    case GET_CONF_SORM:
        rc = ssh_channel_request_exec(channel, instruction_get_sorm.toLocal8Bit().data());
        break;
    case GET_CONF_XMANAGER:
        rc = ssh_channel_request_exec(channel, instruction_get_xmanager.toLocal8Bit().data());
        break;
    case GET_CONF_CZ_1:
        rc = ssh_channel_request_exec(channel, instruction_get_cz_1.toLocal8Bit().data());
        break;
    case GET_CONF_CZ_2:
        rc = ssh_channel_request_exec(channel, instruction_get_cz_2.toLocal8Bit().data());
        break;
    case SET_CONF_CZ_1:
        // Для вставки сразу нескольких значений использовать ключ -i -e '/asd/asd/; /asd/asd/'
//        rc = ssh_channel_request_exec(channel,
//                                      QString("sed -i \"/^%1/c htg_s4g_mt_affinity_mask=0x000ffff\" " +
//                                      config_path + "cenzor/cenzor.test.ini").arg("htg_s4g_mt_affinity_mask=").toStdString().data());
        std::cout << QString("sed -i \"/^%1/c htg_s4g_mt_affinity_mask=0x000ffff\" " +
                             config_path + "cenzor/cenzor.test.ini").arg("htg_s4g_mt_affinity_mask=").toStdString() << std::endl;
        foreach (QString var, affinity->GetMapModified().keys()) {
            QString key, value;
            if (var.split('|').at(0) == "Cenzor_1") {
               key = var.split('/').at(1);
               value = affinity->GetMapModified().value(var);
               qDebug().noquote() << QString("sed -i \"/^" + key + "=/c " + key + '=' + value + "\" " + config_path +
                                   "cenzor/cenzor.1.ini");
               rc = ssh_channel_request_exec(channel, QString("sed -i \"/^" + key +
                                           "=/c " + key + '=' + value + "\" " + config_path +
                                                              "cenzor/cenzor.1.ini").toStdString().data());

               qDebug() << "channel free";
            }
        }
        break;
    case SET_CONF_SORM:
        // Регулярка вставки значения при известном ключе
        // sed '/SORM/s/\(affinity_low=\"\)[0-9aAbBcCdDeEfFx]\{1,\}\"/\10x01111\"/' ./sorm_test.xml
        // Для вставки сразу нескольких значений использовать ключ -i -e '/asd/asd/; /asd/asd/'
        {QString str = "0x011011101";
        qDebug() << QString("sed -i '/SORM/s/\(affinity_high=\"\\)[0-9aAbBcCdDeEfFx]\{1,\\}\"/\1" +
                            str + "\"/' " + config_path + "sorm/sorm.xml").toStdString().data();
        rc = ssh_channel_request_exec(channel,
                    QString("sed -i '/SORM/s/\\(affinity_high=\"\\)[0-9aAbBcCdDeEfFx]\\{1,\\}\"/\\1" +
                            str + "\"/' " + config_path + "sorm/sorm.xml").toStdString().data());
        break;}
    default:
        break;
    }

    if (rc != SSH_OK)
    {
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    return rc;
    }

    qDebug() << "Remote_act: before IF";
    if(gs) {
        nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
        while (nbytes > 0)
        {
            tst_str.append(buffer);
            nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);

        }
        instructions_and_results[order] = QString(tst_str.data());
        if (nbytes < 0)
        {
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return SSH_ERROR;
        }

    }else{
        qDebug() << tst_str.data();
    }


    ssh_channel_send_eof(channel);
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    qDebug() << "Remote_act: DONE";
    return SSH_OK;
}



// ==== SLOTS ====

void WgtForTab::connect_check() {

}

void WgtForTab::OnSaveAffinity() {
    Connect_via_ssh(host_address, login, password);
//    Remote_act(SET_CONF_CZ_1, false) ? qDebug() << "true" : qDebug() << "false";
    Remote_act(SET_CONF_SORM, false);
    StopSSHSess();
}

void WgtForTab::GetContent() {
    Connect_via_ssh(host_address, login, password);
    switch (srv_type) {
    {case Type_Server::UNDEF:

            break;}
    case Type_Server::SMNK139:
        break;
    case Type_Server::R:
        break;
    case Type_Server::GE:
        break;
    case Type_Server::MO:
//        Remote_act(instruction_get_dragonet);
//        manager->SetText(instructions_and_results[instruction_get_dragonet].data());
//        Remote_act(instruction_get_ipmimon);
//        ipmimon->SetText(instructions_and_results[instruction_get_ipmimon].data());
//        StopSSHSess();
        break;
    case Type_Server::IP:
        break;
    case Type_Server::PD:
        break;
    }


//    boost::asio::io_service io_service;
//    tcp::endpoint ep(boost::asio::ip::address::from_string(strAddr), 2001);
//    boost::asio::ip::tcp::socket sock(io_service);
//    sock.connect(ep);
//    boost::array<char, 1024> arr;
//    boost::system::error_code error;
//    size_t len = sock.read_some(boost::asio::buffer(arr), error);
//    qDebug() << arr.data() << "size " << len;
//    QString str = arr.data();
//    qDebug() << str << "size " << str.size();
//    str.resize(int(len));
//    txt_hostname->setText(str);
//    str.clear();
//    len = sock.read_some(boost::asio::buffer(arr), error);
//    while (len) {
//        qDebug() << arr.data() << "size " << len;
//        str.append(arr.data());
//        len = sock.read_some(boost::asio::buffer(arr), error);
//    }
//    manager_txt_edit_CONST->setText(str);

//    str.clear();
//    len = sock.read_some(boost::asio::buffer(arr), error);
//    while (len) {
//        qDebug() << arr.data() << "size " << len;
//        str.append(arr.data());
//        len = sock.read_some(boost::asio::buffer(arr), error);
//    }
//    manager_txt_edit_INPUTS->setText(str);
//    sock.close();

}

void WgtForTab::Connect_via_ssh(QString host, QString log, QString pass) {
    int verbosity = SSH_LOG_PROTOCOL;
    int port = 22;
    ssh_sess = ssh_new();
    if (ssh_sess == nullptr) exit(-1);
    ssh_options_set(ssh_sess, SSH_OPTIONS_HOST, host.toUtf8().constData());
    ssh_options_set(ssh_sess, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
    ssh_options_set(ssh_sess, SSH_OPTIONS_USER, log.toUtf8().constData());
    ssh_options_set(ssh_sess, SSH_OPTIONS_PORT, &port);

    int rc = ssh_connect(ssh_sess);
    if(rc != SSH_OK) {
        std::cout << "Can't connect!" << std::endl;
        ssh_free(ssh_sess);
        exit(-1);
    }

    if(Verify_knownhost(ssh_sess) < 0) {
        std::cout << "Verify false!" << std::endl;
        ssh_disconnect(ssh_sess);
        ssh_free(ssh_sess);
        exit(-1);
    }

//    char pass[] = "Adid@$";
    rc = ssh_userauth_password(ssh_sess, nullptr, pass.toUtf8().constData());
//    std::cout << ((rc != SSH_AUTH_SUCCESS) ? "Auth isn't successfull\n" : "Auth is successfull\n" );
//    (rc != SSH_AUTH_SUCCESS) ? lbl_hostname->setStyleSheet("QLabel { background-color : red }"):
//                               lbl_hostname->setStyleSheet("QLabel { background-color : green }");

}

void WgtForTab::StopSSHSess() {
    ssh_disconnect(ssh_sess);
    ssh_free(ssh_sess);
}

// ==== WgtCPUAffinity ====
// ---- CPUCoreButton ---->
CPUCoreButton::CPUCoreButton(int core_num, QWidget* prnt) : QPushButton(prnt) {
    setText(QString::number(core_num));
    setFixedSize(25, 25);
    inUse = false;
    pal = palette();
    pal.setColor(QPalette::Button, QColor(Qt::blue));
    setAutoFillBackground(true);
    setPalette(pal);
    update();

    connect(this, SIGNAL(clicked()), this, SLOT(OnClicked()));
}

bool CPUCoreButton::getState() {
    return inUse;
}

void CPUCoreButton::setState(Statement st) {
    switch (st) {
    case FREE:
        inUse = false;
        pal.setColor(QPalette::Button, QColor(Qt::blue));
        setPalette(pal);
        update();
        statement = st;
        break;
    case SINGLE_USE:
        inUse = true;
        pal.setColor(QPalette::Button, QColor(Qt::green));
        setPalette(pal);
        update();
        statement = st;
        break;
    case MULTI_USE:
        inUse = true;
        pal.setColor(QPalette::Button, QColor(Qt::yellow));
        setPalette(pal);
        update();
        statement = st;
        break;
    case SYSTEM:
        inUse = false;
        pal.setColor(QPalette::Button, QColor(Qt::red));
        setPalette(pal);
        update();
        statement = st;
        break;
    }
}

void CPUCoreButton::OnClicked() {
    getState() ? setState(Statement::FREE) : setState(Statement::SINGLE_USE);
    emit chpock();
}

// <---- CPUCoreButton ----
// ---- InfoMessage ---->
InfoMessage::InfoMessage(QString message, QWidget *prnt) : QWidget(prnt){
    setWindowFlags(Qt::Window
                   );
    setWindowTitle("ВНИМАНИЕ!");
    lot = new QVBoxLayout;
    lbl_message = new QLabel(message);
    btn_ok = new QPushButton("OK");
    lot->addWidget(lbl_message);
    lot->addWidget(btn_ok);
    setLayout(lot);

    connect(btn_ok, SIGNAL(clicked()), this, SLOT(close()));
}
// <---- InfoMessage ----
WgtCPUAffinity::WgtCPUAffinity(const QMap<Orders, QString> & instructions_and_results, QWidget *prnt) : QWidget(prnt) {
//    qDebug() << "Current instructions" << instructions_and_results.keys();
//    qDebug() << "Current instructions" << instructions_and_results.values();
    SetCPUCount(instructions_and_results.value(GET_NODES_COUNT).toInt());
    SetCoresCount(instructions_and_results.value(GET_CPUS_COUNT).toInt());
    centralLayout = new QBoxLayout(QBoxLayout::TopToBottom);
    setLayout(centralLayout);
    hlt = new QHBoxLayout;
    centralLayout->addLayout(hlt);
    wgt_list_modules = new QTreeWidget();
    wgt_list_modules->setFixedWidth(325);
    wgt_list_modules->setHeaderLabel("Модули");
    hlt->addWidget(wgt_list_modules);

    foreach (Orders ord, instructions_and_results.keys()) {
        QStringList str = GetModuleName(ord);
        if (str.isEmpty()) continue;
        if (str.count() == 1) {
            // Регулярка взятия подстроки ключ=значение
            QRegExp rx(str.at(0).split('/').at(1) + '=' + "\"{0,1}\\d{1}x{0,1}[0-9aAbBcCdDeEfF]{1,}");
            if (rx.indexIn(instructions_and_results.value(ord), 0) != -1) {
                // Регулярка взятия подстроки только значения ключа
                QRegExp rxf("\\d{1}x{0,1}[0-9aAbBcCdDeEfF]{1,}");
                rxf.indexIn(rx.cap(0));
//                qDebug() << rxf.cap(0);
                modules_affinity_original[str.at(0)] = rxf.cap(0);
                modules_affinity_modified[str.at(0)] = rxf.cap(0);
            }
        }else{
            foreach (QString str_buf, str) {
                // Регулярка взятия подстроки ключ=значение
                QRegExp rx(str_buf.split('/').at(1) + '=' + "\"{0,1}\\d{1}x{0,1}[0-9aAbBcCdDeEfF]{1,}");
                if (rx.indexIn(instructions_and_results.value(ord), 0) != -1) {
                    // Регулярка взятия подстроки только значения ключа
                    QRegExp rxf("\\d{1}x{0,1}[0-9aAbBcCdDeEfF]{1,}");
                    rxf.indexIn(rx.cap(0));
//                    qDebug() << rxf.cap(0);
                    modules_affinity_original[str_buf] = rxf.cap(0);
                    modules_affinity_modified[str_buf] = rxf.cap(0);
                }
            }
        }
    }
// Создание дерева модулей
    QStringList prnts_list;
    QMap<QString, QTreeWidgetItem*> prnts;
//    qDebug() << "Creating tree: check 8";
    foreach (QString str, modules_affinity_original.keys()) {
        wgt_list_modules->setAutoScroll(true);
        if (str.contains('|')) {
            QString tmp_str_prnt = str.split('|').at(0);
            if (prnts_list.contains(tmp_str_prnt)){
                item_module = new QTreeWidgetItem(prnts.value(tmp_str_prnt));
                item_module->setText(0, str.split('/').at(0).split('|').at(1));
                item_module->setText(1, str);
            }else{
                // Создание родителя (только текст в дереве)
                item_module = new QTreeWidgetItem(wgt_list_modules);
                prnts[tmp_str_prnt] = item_module;
                prnts_list.push_back(tmp_str_prnt);
                item_module->setText(0, tmp_str_prnt);
                QTreeWidgetItem* item_chld = new QTreeWidgetItem(item_module);
                item_chld->setText(0, str.split('/').at(0).split('|').at(1));
                item_chld->setText(1, str);
            }
        }else{
            item_module = new QTreeWidgetItem(wgt_list_modules);
            item_module->setText(0, str.split('/').at(0));
            item_module->setText(1, str);
        }

    }
    wgt_list_modules->setCurrentItem(wgt_list_modules->itemAt(0,0));
    wgt_list_modules->itemAt(0,0)->setSelected(true);
    // ==== Test ====>/

    // <==== Test ==== В шатаном режиме сначала считывание кол-ва ЦПУ и ядер
    group_cores = new QGroupBox("Cores");
    QVBoxLayout* vlt_cores = new QVBoxLayout;
    lbl_CPUS_count_HEX_low = new QLabel("0x");
    vlt_cores->addWidget(lbl_CPUS_count_HEX_low);
    if (cores_count > 56) {
        lbl_CPUS_count_HEX_high = new QLabel("0x");
        vlt_cores->addWidget(lbl_CPUS_count_HEX_high);
    }

    int check = cores_count / cpus_count;
    switch (cpus_count) {
    case 1:{
        vct_hlt.push_back(new QHBoxLayout);
        vlt_cores->addLayout(vct_hlt.at(0));
        int half = cores_count /2;
        for(int core_num = 0; core_num < cores_count; core_num++) {
//            vct_check_box.push_back(new QCheckBox(QString::number(core_num)));
//            vct_hlt.at(0)->addWidget(vct_check_box.at(core_num));
            vct_buttons.push_back(new CPUCoreButton(core_num));
            vct_hlt.at(0)->addWidget(vct_buttons.at(core_num));
           if(core_num == (half - 1))  vct_hlt.at(0)->addSpacing(25);
        }
        break;}
    case 2: {
        int quarter = cores_count / 4;
        for(int cpu_num = 0; cpu_num < cpus_count; cpu_num++) {
            vct_hlt.push_back(new QHBoxLayout);
            vlt_cores->addLayout(vct_hlt.at(cpu_num));
            if (cpu_num == 0) {
                for(int core_num = 0; core_num < check; core_num++) {
//                    vct_check_box.push_back(new QCheckBox(core_num < 10 ? QString::number(core_num).prepend("0")
//                                                                        : QString::number(core_num)));
//                    vct_hlt.at(cpu_num)->addWidget(vct_check_box.at(core_num));
//                    connect(vct_check_box.at(core_num), SIGNAL(clicked()), this, SLOT(On_CheckBox_Clicked()));
                    vct_buttons.push_back(new CPUCoreButton(core_num));
                    vct_hlt.at(cpu_num)->addWidget(vct_buttons.at(core_num));
                    connect(vct_buttons.at(core_num), SIGNAL(chpock()), this, SLOT(OnCPUButtonChpock()));
                   if(core_num == (quarter - 1))  vct_hlt.at(cpu_num)->addSpacing(30);
                }
            }else{
                for(int core_num = check; core_num < cores_count; core_num++) {
//                    vct_check_box.push_back(new QCheckBox(QString::number(core_num)));
//                    vct_hlt.at(cpu_num)->addWidget(vct_check_box.at(core_num));
//                    connect(vct_check_box.at(core_num), SIGNAL(clicked()), this, SLOT(On_CheckBox_Clicked()));
                    vct_buttons.push_back(new CPUCoreButton(core_num));
                    vct_hlt.at(cpu_num)->addWidget(vct_buttons.at(core_num));
                   if(core_num == (quarter * 3 - 1))  vct_hlt.at(cpu_num)->addSpacing(30);
                   connect(vct_buttons.at(core_num), SIGNAL(chpock()), this, SLOT(OnCPUButtonChpock()));
                }
            }
        }
        break;}
    default:
        std::cout << "Wrong CPU's count " <<std::endl;
        break;
    qDebug() << "CPUAffinity DONE";
    }

    SetChecks(modules_affinity_original.value(wgt_list_modules->currentItem()->text(1)));

    group_cores->setLayout(vlt_cores);
    // ==== Test ====/
    hlt->addWidget(group_cores);

    // ==== Signals&Slots ====
    connect(wgt_list_modules, SIGNAL(currentItemChanged(QTreeWidgetItem*, QTreeWidgetItem*)),
            SLOT(List_modules_row_changed(QTreeWidgetItem*, QTreeWidgetItem*)));


}

void WgtCPUAffinity::SetCPUCount(int cpu_count) {
    cpus_count = cpu_count;
}

void WgtCPUAffinity::SetCoresCount(int core_count) {
    cores_count = core_count;
}

QString WgtCPUAffinity::GetAffinity(){
    QString result;
    for (int core_num = 0; core_num < cores_count; core_num++) {
//        vct_check_box.at(core_num)->isChecked() ? result.prepend("1") : result.prepend("0");
        vct_buttons.at(core_num)->getState() ? result.prepend("1") : result.prepend("0");
    }
    return result;
}

void WgtCPUAffinity::SetChecks(QString affinity) {
    if(affinity.isEmpty()) {
        lbl_CPUS_count_HEX_low->setText("Error");
    } else {
        bool ok;
        QString binary = QString::number(affinity.toLongLong(&ok, 16), 2);
        if (cores_count < binary.size()) {
            InfoMessage* message = new InfoMessage("Кол-во ядер (" + QString::number(cores_count) + ") меньше, чем настроенная привязка ("
                                + QString::number(binary.size()) + ")");
            message->show();
            return;
        }
        lbl_CPUS_count_HEX_low->setText(affinity);
        foreach (CPUCoreButton* button, vct_buttons) {
            button->setState(Statement::FREE);
        }
        int counter = 0;
        for (int cnt = binary.size() - 1; cnt >= 0; cnt--) {
            (binary.at(cnt) == '1') ? vct_buttons.at(counter++)->setState(Statement::SINGLE_USE):
                       vct_buttons.at(counter++)->setState(Statement::FREE);
        }
    }

}

QStringList WgtCPUAffinity::GetModuleName(Orders ord) {
    QStringList result;
    result.clear();
    switch (ord) {
    case GET_CONF_IPMIMON:
        result.push_back("IpmiMon/AffinityMask value");
        break;
    case GET_CONF_REPLICATOR:
        result.push_back("Replicator/cpu_affinity_mask");
        break;
    case GET_CONF_SORM:
        result.push_back("Sorm/affinity_low");
        break;
    case GET_CONF_XMANAGER:
        result.push_back("Xmanager/cpu_affinity_mask");
        break;
    case GET_CONF_CZ_1:
        result.push_back("Cenzor_1|HTG маска/htg_s4g_mt_affinity_mask");
        result.push_back("Cenzor_1|(L)ПП/process_affinity");
        result.push_back("Cenzor_1|(L)ПП входных сет потоков/in_net_pins_thread_affinity");
        result.push_back("Cenzor_1|(L)ПП входных PCAP потоков/in_pcap_pins_thread_affinity");
        result.push_back("Cenzor_1|(L)ПП входных HTG потоков/in_hardware_io_pins_thread_affinity");
        result.push_back("Cenzor_1|(L)ПП входных файловых потоков/in_file_pins_thread_affinity");
        result.push_back("Cenzor_1|(L)ПП рабочих потоков/worker_thread_affinity");
        result.push_back("Cenzor_1|(L)ПП выходных потоков/out_pins_thread_affinity");
        break;
    case GET_CONF_CZ_2:
        result.push_back("Cenzor_2|HTG маска/htg_s4g_mt_affinity_mask");
        result.push_back("Cenzor_2|(L)ПП/process_affinity");
        result.push_back("Cenzor_2|(L)ПП входных сет потоков/in_net_pins_thread_affinity");
        result.push_back("Cenzor_2|(L)ПП входных PCAP потоков/in_pcap_pins_thread_affinity");
        result.push_back("Cenzor_2|(L)ПП входных HTG потоков/in_hardware_io_pins_thread_affinity");
        result.push_back("Cenzor_2|(L)ПП входных файловых потоков/in_file_pins_thread_affinity");
        result.push_back("Cenzor_2|(L)ПП рабочих потоков/worker_thread_affinity");
        result.push_back("Cenzor_2|(L)ПП выходных потоков/out_pins_thread_affinity");
        break;
    default:
        break;
    }
    return result;
}

QMap<QString, QString> WgtCPUAffinity::GetMapOriginal() {
    return modules_affinity_original;
}

QMap<QString, QString> WgtCPUAffinity::GetMapModified() {
    return modules_affinity_modified;
}

// ==== Slots ====

void WgtCPUAffinity::List_modules_row_changed(QTreeWidgetItem* current, QTreeWidgetItem* previous) {
    if (current->childCount() != 0) return;     //Доделать! Изоляция настроек корневого элемента (например Cenzor)
    if(current != previous) {
        QString affinity;
        affinity = modules_affinity_modified.value(current->text(1));
        SetChecks(affinity);
    }
}

void WgtCPUAffinity::On_CheckBox_Clicked(){
    bool ok;
    QString hex_value = "0x" + QString("%1").arg(GetAffinity().toULongLong(&ok, 2),
                                                 15, 16, QChar('0'));
    lbl_CPUS_count_HEX_low->setText(hex_value);
    if(wgt_list_modules->currentItem()->parent()) {
        modules_affinity[(wgt_list_modules->currentItem()->parent()->text(0)
                          + "|" + wgt_list_modules->currentItem()->text(0))] = hex_value;
    } else {
        modules_affinity[(wgt_list_modules->currentItem()->text(0))] = hex_value;
    }

}

void WgtCPUAffinity::OnCPUButtonChpock(){
    bool ok;
    QString hex_value = "0x" + QString("%1").arg(GetAffinity().toULongLong(&ok, 2),
                                                 15, 16, QChar('0'));
    lbl_CPUS_count_HEX_low->setText(hex_value);
    if(wgt_list_modules->currentItem()->parent()) {
        modules_affinity[(wgt_list_modules->currentItem()->parent()->text(0)
                          + "|" + wgt_list_modules->currentItem()->text(0))] = hex_value;
    } else {
        modules_affinity[(wgt_list_modules->currentItem()->text(0))] = hex_value;
    }
}

// ==== WgtTextEdit ====

WgtTextEdit::WgtTextEdit(QString lbl, QWidget* prnt) : QWidget(prnt) {
    lot_cntrl = new QBoxLayout(QBoxLayout::TopToBottom);
    setLayout(lot_cntrl);
    header = new QLabel(lbl);
    txt = new QTextEdit;

    lot_cntrl->addWidget(header);
    lot_cntrl->addWidget(txt);

    setMinimumHeight(600);
}

void WgtTextEdit::SetText(QString string) {
    txt->setText(string);
}
// ==== WgtCenzorConfig ====

WgtCenzorConfig::WgtCenzorConfig(QWidget* prnt) : QWidget(prnt) {
//    lot_main = new QGridLayout;
    gp_box = new QGroupBox(this);

}

// ==== WgtWrhgConfig ====

WgtWrhgConfig::WgtWrhgConfig(QWidget* prnt) : QWidget(prnt) {

}


