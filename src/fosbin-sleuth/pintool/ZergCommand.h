//
// Created by derrick on 2/14/19.
//

#ifndef FOSBIN_ZERGCOMMAND_H
#define FOSBIN_ZERGCOMMAND_H

typedef enum zerg_message_type {
    ZMSG_FAIL = -1,
    ZMSG_OK,
    ZMSG_SET_TGT,
    ZMSG_EXIT,
    ZMSG_FUZZ,
    ZMSG_EXECUTE,
    ZMSG_SET_CTX,
    ZMSG_RESET
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
};

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
    virtual zerg_cmd_result_t execute();

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

#include "ZergCommand.cpp"

#endif //FOSBIN_ZERGCOMMAND_H
