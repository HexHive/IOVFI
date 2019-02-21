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
            return new FuzzCommand(msg, server);
        case ZMSG_EXECUTE:
            return new ExecuteCommand(msg, server);
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
        case ZCMD_OK:
            return "OK";
        case ZCMD_ERROR:
            return "ERROR";
        case ZCMD_NOT_FOUND:
            return "NOT_FOUND";
        case ZCMD_INTERRUPTED:
            return "INTERRUPTED";
        case ZCMD_TOO_MANY_INS:
            return "TOO_MANY_INS";
        case ZCMD_FAILED_CTX:
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
        return ZCMD_ERROR;
    }
    return ZCMD_OK;
}

zerg_cmd_result_t InvalidCommand::execute() {
    std::cout << "InvalidCommand executed" << std::endl;
    return ZCMD_ERROR;
}

InvalidCommand::InvalidCommand(ZergMessage &msg, ZergCommandServer &server) :
        ZergCommand(msg, server) {}

zerg_cmd_result_t ExitCommand::execute() {
    std::cout << "Stopping server" << std::endl;
    server_.stop();
    return ZCMD_OK;
}

ExitCommand::ExitCommand(ZergMessage &msg, ZergCommandServer &server) :
        ZergCommand(msg, server) {}

zerg_cmd_result_t ResetCommand::execute() {
    if (!server_.set_state(ZERG_SERVER_WAIT_FOR_CMD)) {
        return ZCMD_ERROR;
    }
    return ZCMD_OK;
}

ResetCommand::ResetCommand(ZergMessage &msg, ZergCommandServer &server) :
        ZergCommand(msg, server) {}

zerg_cmd_result_t FuzzCommand::execute() {
    if (!server_.set_state(ZERG_SERVER_FUZZING)) {
        return ZCMD_ERROR;
    }

    if (server_.write_to_executor(msg_) == 0) {
        return ZCMD_ERROR;
    }

    return ZCMD_OK;
}

FuzzCommand::FuzzCommand(ZergMessage &msg, ZergCommandServer &server) :
        ZergCommand(msg, server) {}

zerg_cmd_result_t ExecuteCommand::execute() {
    if (!server_.set_state(ZERG_SERVER_EXECUTING)) {
        return ZCMD_ERROR;
    }

    if (server_.write_to_executor(msg_) == 0) {
        return ZCMD_ERROR;
    }
    return ZCMD_OK;
}

ExecuteCommand::ExecuteCommand(ZergMessage &msg, ZergCommandServer &server) :
        ZergCommand(msg, server) {}