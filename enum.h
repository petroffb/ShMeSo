#ifndef ENUM_H
#define ENUM_H
enum Type_Server{UNDEF = 0, GE, R, MO, IP, PD, SMNK139}; // Тип сервера

enum Orders{
    GET_HOSTNAME = 1,
    GET_NODES_COUNT,
    GET_CPUS_COUNT,
    GET_CONF_SORM = 100,
    GET_CONF_IPMIMON,
    GET_CONF_DRAGONET,
    GET_CONF_XMANAGER,
    GET_CONF_REPLICATOR,    
    GET_CONF_CZ_1,
    GET_CONF_CZ_2,
    SET_CONF_CZ_1 = 300,
    SET_CONF_CZ_2
};

enum Statement{FREE = 0, SINGLE_USE, MULTI_USE, SYSTEM}; // Состояния кнопок виджета проц-й привязки
#endif // ENUM_H
