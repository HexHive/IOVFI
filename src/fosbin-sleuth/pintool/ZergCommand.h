//
// Created by derrick on 2/14/19.
//

#ifndef FOSBIN_ZERGCOMMAND_H
#define FOSBIN_ZERGCOMMAND_H

typedef int zerg_cmd_t;
typedef enum zerg_cmd_result_t_ {
    OK = 1,
    ERROR,
    NOT_FOUND,
    INTERRUPTED,
    TOO_MANY_INS,
    FAILED_CTX
} zerg_cmd_result_t;

class ZergCommandServer;

class ZergCommand {
public:
    virtual zerg_cmd_result_t execute() = 0;

    static ZergCommand *create(zerg_cmd_t type, ZergCommandServer &server);

    static const char *result_to_str(zerg_cmd_result_t result);

    virtual ~ZergCommand();

protected:
    ZergCommand(zerg_cmd_t type, ZergCommandServer &server);

    ZergCommandServer &server_;
    zerg_cmd_t type_;

    void log(std::stringstream &msg);
};

class SetTargetCommand : public ZergCommand {
public:
    virtual zerg_cmd_result_t execute();

    SetTargetCommand(ZergCommandServer &server);

    const static zerg_cmd_t COMMAND_ID;
protected:
    uintptr_t new_target_;
};

class InvalidCommand : public ZergCommand {
public:
    virtual zerg_cmd_result_t execute();

    InvalidCommand(ZergCommandServer &server);

    const static zerg_cmd_t COMMAND_ID;
};

class ExitCommand : public ZergCommand {
public:
    virtual zerg_cmd_result_t execute();

    ExitCommand(ZergCommandServer &server);

    const static zerg_cmd_t COMMAND_ID;
};

class FuzzCommand : public ZergCommand {
public:
    virtual zerg_cmd_result_t execute();

    FuzzCommand(ZergCommandServer &server);

    const static zerg_cmd_t COMMAND_ID;
};

class ExecuteCommand : public ZergCommand {
public:
    virtual zerg_cmd_result_t execute();

    ExecuteCommand(ZergCommandServer &server);

    const static zerg_cmd_t COMMAND_ID;
};

class GetServerStateCommand : public ZergCommand {
public:
    virtual zerg_cmd_result_t execute();

    GetServerStateCommand(ZergCommandServer &server);

    const static zerg_cmd_t COMMAND_ID;
};

#include "ZergCommand.cpp"

#endif //FOSBIN_ZERGCOMMAND_H
