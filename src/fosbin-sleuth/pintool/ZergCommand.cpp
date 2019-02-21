//
// Created by derrick on 2/14/19.
//

#include "ZergCommand.h"
#include "ZergCommandServer.h"

ZergCommand::ZergCommand(ZergMessage &msg, ZergCommandServer &server) :
        server_(server),
        msg_(msg) {
}

ZergCommand::~ZergCommand() {}

ZergCommand *ZergCommand::create(ZergMessage &msg, ZergCommandServer &server) {
    switch (msg.type()) {
        case ZMSG_SET_TGT:
            return new ZergCommand(msg, server);
        case ZMSG_EXIT:
            return new ExitCommand(msg, server);
        case ZMSG_FUZZ:
            return new ZergCommand(msg, server);
        case ZMSG_EXECUTE:
            return new ZergCommand(msg, server);
        case ZMSG_SET_CTX:
            return new ZergCommand(msg, server);
        case ZMSG_RESET:
            return new ResetCommand(msg, server);
        default:
            return new InvalidCommand(msg, server);
    }
}

const char *ZergCommand::result_to_str(zerg_cmd_result_t result) {
    std::stringstream ss;
    switch (result) {
        case OK:
            return "OK";
        case ERROR:
            return "ERROR";
        case NOT_FOUND:
            return "NOT_FOUND";
        case INTERRUPTED:
            return "INTERRUPTED";
        case TOO_MANY_INS:
            return "TOO_MANY_INS";
        case FAILED_CTX:
            return "FAILED_CTX";
        default:
            ss << "UNKNOWN: " << result;
            return ss.str().c_str();
    }
};

void ZergCommand::log(std::stringstream &msg) {
    std::cout << msg.str() << std::endl;
    msg.str(std::string());
}

zerg_cmd_result_t ZergCommand::execute() {
    if (server_.write_to_executor(msg_) == 0) {
        return ERROR;
    }
    return OK;
}

zerg_cmd_result_t InvalidCommand::execute() {
    std::cout << "InvalidCommand executed" << std::endl;
    return ERROR;
}

InvalidCommand::InvalidCommand(ZergMessage &msg, ZergCommandServer &server) :
        ZergCommand(msg, server) {}

zerg_cmd_result_t ExitCommand::execute() {
    std::cout << "Stopping server" << std::endl;
    server_.stop();
    return OK;
}

ExitCommand::ExitCommand(ZergMessage &msg, ZergCommandServer &server) :
        ZergCommand(msg, server) {}

zerg_cmd_result_t ResetCommand::execute() {
    if (!server_.set_state(ZERG_SERVER_WAIT_FOR_CMD)) {
        return ERROR;
    }
    return OK;
}

ResetCommand::ResetCommand(ZergMessage &msg, ZergCommandServer &server) :
        ZergCommand(msg, server) {}

ZergMessage::ZergMessage(zerg_message_t type) :
        _message_type(type), _length(0), _data(nullptr), _self_allocated_data(false) {}

ZergMessage::ZergMessage(zerg_message_t type, size_t length, void *data) :
        _message_type(type), _length(length), _data(data), _self_allocated_data(false) {}

ZergMessage::ZergMessage(const ZergMessage &msg) {
    _message_type = msg._message_type;
    _length = msg._length;

    if (msg._length > 0) {
        _self_allocated_data = true;
        _data = malloc(msg._length);
        memcpy(_data, msg._data, _length);
    } else {
        _data = nullptr;
        _self_allocated_data = false;
    }
}

ZergMessage::~ZergMessage() {
    if (_self_allocated_data) {
        free(_data);
    }
}

size_t ZergMessage::size() const { return _length; }

zerg_message_t ZergMessage::type() const { return _message_type; }

void *ZergMessage::data() const { return _data; }

size_t ZergMessage::write_to_fd(int fd) const {
    size_t written = 0;
    int tmp = write(fd, &_message_type, sizeof(_message_type));
    if (tmp <= 0) {
        return 0;
    }

    written += tmp;
    tmp = write(fd, &_length, sizeof(_length));
    if (tmp <= 0) {
        return 0;
    }

    written += tmp;
    if (_length > 0) {
        tmp = write(fd, _data, _length);
        if (tmp <= 0) {
            return 0;
        }
        written += tmp;
    }

    return written;
}

size_t ZergMessage::read_from_fd(int fd) {
    size_t read_bytes = 0;
    zerg_message_t msg_type;
    size_t length;
    void *data = nullptr;

    int tmp = read(fd, &msg_type, sizeof(msg_type));
    if (tmp <= 0) {
        return 0;
    }
    read_bytes += tmp;

    tmp = read(fd, &length, sizeof(length));
    if (tmp <= 0) {
        return 0;
    }
    read_bytes += tmp;

    if (length > 0) {
        data = malloc(length);
        if (!data) {
            return 0;
        }

        tmp = read(fd, data, length);
        if (read <= 0) {
            free(data);
            return 0;
        }
        read_bytes += tmp;
    }

    _message_type = msg_type;
    _length = length;
    if (data) {
        _data = data;
        _self_allocated_data = true;
    } else {
        _self_allocated_data = false;
    }

    return read_bytes;
}
