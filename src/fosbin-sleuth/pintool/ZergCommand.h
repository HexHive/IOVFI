//
// Created by derrick on 2/14/19.
//

#ifndef FOSBIN_ZERGCOMMAND_H
#define FOSBIN_ZERGCOMMAND_H

typedef enum zerg_message_type {
    ZMSG_FAIL = -1,
    ZMSG_OK,
    ZMSG_ACK,
    ZMSG_SET_TGT,
    ZMSG_EXIT,
    ZMSG_FUZZ,
    ZMSG_EXECUTE,
    ZMSG_SET_CTX,
    ZMSG_RESET,
    ZMSG_READY,
    ZMSG_SET_SO_TGT,
    ZMSG_GET_EXE_INFO,
    ZMSG_SET_RUST_TGT
} zerg_message_t;

class ZergMessage {
protected:
    zerg_message_t _message_type;
    size_t _length;
    void *_data;
    bool _self_allocated_data;
public:
    ZergMessage(zerg_message_t type, size_t length, void *data);

    ZergMessage(zerg_message_t type = ZMSG_FAIL);

    ZergMessage(const ZergMessage &msg);

    ~ZergMessage();

    size_t read_from_fd(int fd);

    size_t write_to_fd(int fd) const;

    size_t size() const;

    zerg_message_t type() const;

    void *data() const;

    const char *str() const;

    size_t add_contexts(const FBZergContext &pre, const FBZergContext &post);

    size_t add_exe_info(const ExecutionInfo &info);
};

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

#include "ZergCommand.cpp"
#include "ZergMessage.cpp"

#endif //FOSBIN_ZERGCOMMAND_H
