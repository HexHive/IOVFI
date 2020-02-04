//
// Created by derrick on 2/14/19.
//

#ifndef FOSBIN_ZERGCOMMAND_H
#define FOSBIN_ZERGCOMMAND_H

#include "ZergMessage.h"
#include "ZergCommandServer.h"

typedef enum zerg_cmd_result_t_ {
    ZCMD_OK = 1,
    ZCMD_ERROR,
    ZCMD_NOT_FOUND,
    ZCMD_INTERRUPTED,
    ZCMD_TOO_MANY_INS,
    ZCMD_FAILED_CTX
} zerg_cmd_result_t;

class ZergCommandServer;

class ZergCommand {
public:
    virtual zerg_cmd_result_t execute() = 0;

    static ZergCommand *create(ZergMessage &msg, ZergCommandServer &server);

    static const char *result_to_str(zerg_cmd_result_t result);

    virtual ~ZergCommand();

protected:
    ZergCommand(ZergMessage &msg, ZergCommandServer &server);

    ZergCommandServer &server_;
    ZergMessage msg_;

    void log(std::stringstream &msg);
};

class InvalidCommand : public ZergCommand {
public:
    virtual zerg_cmd_result_t execute();

    InvalidCommand(ZergMessage &msg, ZergCommandServer &server);
};

class ExitCommand : public ZergCommand {
public:
    virtual zerg_cmd_result_t execute();

    ExitCommand(ZergMessage &msg, ZergCommandServer &server);
};

class ResetCommand : public ZergCommand {
public:
    virtual zerg_cmd_result_t execute();

    ResetCommand(ZergMessage &msg, ZergCommandServer &server);
};

class FuzzCommand : public ZergCommand {
public:
    virtual zerg_cmd_result_t execute();

    FuzzCommand(ZergMessage &msg, ZergCommandServer &server);
};

class ExecuteCommand : public ZergCommand {
public:
    virtual zerg_cmd_result_t execute();

    ExecuteCommand(ZergMessage &msg, ZergCommandServer &server);
};

class SetTargetCommand : public ZergCommand {
public:
    virtual zerg_cmd_result_t execute();

    SetTargetCommand(ZergMessage &msg, ZergCommandServer &server);
};

class SetContextCommand : public ZergCommand {
public:
    virtual zerg_cmd_result_t execute();

    SetContextCommand(ZergMessage &msg, ZergCommandServer &server);
};

class SetSharedTargetCommand : public SetTargetCommand {
public:
    SetSharedTargetCommand(ZergMessage &msg, ZergCommandServer &server);
};

class SendExecuteInfoCommand : public ZergCommand {
public:
    virtual zerg_cmd_result_t execute();

    SendExecuteInfoCommand(ZergMessage &msg, ZergCommandServer &server);
};

#endif //FOSBIN_ZERGCOMMAND_H
