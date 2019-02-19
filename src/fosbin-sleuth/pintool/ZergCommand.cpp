//
// Created by derrick on 2/14/19.
//

#include "ZergCommand.h"
#include "ZergCommandServer.h"

const zerg_cmd_t SetTargetCommand::COMMAND_ID = 1;
const zerg_cmd_t InvalidCommand::COMMAND_ID = 2;
const zerg_cmd_t ExitCommand::COMMAND_ID = 3;
const zerg_cmd_t FuzzCommand::COMMAND_ID = 4;
const zerg_cmd_t ExecuteCommand::COMMAND_ID = 5;
const zerg_cmd_t GetServerStateCommand::COMMAND_ID = 6;

ZergCommand::ZergCommand(zerg_cmd_t type, ZergCommandServer &server) :
        server_(server),
        type_(type) {}

ZergCommand::~ZergCommand() {}

ZergCommand *ZergCommand::create(zerg_cmd_t type, ZergCommandServer &server) {
    switch (type) {
        case SetTargetCommand::COMMAND_ID:
            return new SetTargetCommand(server);
        case ExitCommand::COMMAND_ID:
            return new ExitCommand(server);
        case FuzzCommand::COMMAND_ID:
            return new FuzzCommand(server);
        case ExecuteCommand::COMMAND_ID:
            return new ExecuteCommand(server);
        case GetServerStateCommand::COMMAND_ID:
            return new GetServerStateCommand(server);
        default:
            return new InvalidCommand(server);
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
    std::cout << msg << std::endl;
    msg.str(std::string());
}

SetTargetCommand::SetTargetCommand(ZergCommandServer &server) :
        ZergCommand(SetTargetCommand::COMMAND_ID, server),
        new_target_(0) {
    std::stringstream msg;
    if (server.read_from_commander((char *) &new_target_, sizeof(new_target_)) < 0) {
        msg << "Error reading new target" << std::endl;
        log(msg);
        return;
    }
    msg << "Read in new target 0x" << std::hex << new_target_;
    log(msg);
}

zerg_cmd_result_t SetTargetCommand::execute() {
    if (new_target_ == 0 || server_.get_state() != ZERG_SERVER_WAIT_FOR_TARGET) {
        return ERROR;
    }

    server_.write_to_executor((char *) &SetTargetCommand::COMMAND_ID, sizeof(SetTargetCommand::COMMAND_ID));
    server_.write_to_executor((char *) &new_target_, sizeof(new_target_));

    zerg_cmd_result_t result;
    server_.read_from_executor(&result, sizeof(result));
    if (result == OK) {
        server_.set_state(ZERG_SERVER_WAIT_FOR_CMD);
    } else {
        std::cout << "CommandServer received " << ZergCommand::result_to_str(result) << std::endl;
    }

    return result;
}

InvalidCommand::InvalidCommand(ZergCommandServer &server) :
        ZergCommand(InvalidCommand::COMMAND_ID, server) {}

zerg_cmd_result_t InvalidCommand::execute() {
    std::cout << "InvalidCommand executed" << std::endl;
    return ERROR;
}

ExitCommand::ExitCommand(ZergCommandServer &server) :
        ZergCommand(ExitCommand::COMMAND_ID, server) {}

zerg_cmd_result_t ExitCommand::execute() {
    std::cout << "Stopping server" << std::endl;
    server_.stop();
    return OK;
}

FuzzCommand::FuzzCommand(ZergCommandServer &server) :
        ZergCommand(FuzzCommand::COMMAND_ID, server) {}

zerg_cmd_result_t FuzzCommand::execute() {
    if (server_.get_state() != ZERG_SERVER_WAIT_FOR_CMD) {
        std::cout << "Invalid state" << std::endl;
        return ERROR;
    }

    zerg_cmd_result_t result;
    if (server_.write_to_executor(&type_, sizeof(type_)) <= 0) {
        return ERROR;
    }
    server_.set_state(ZERG_SERVER_FUZZING);
    if (server_.read_from_executor(&result, sizeof(result)) <= 0) {
        return ERROR;
    }
    server_.set_state(ZERG_SERVER_WAIT_FOR_CMD);

    return result;
}

ExecuteCommand::ExecuteCommand(ZergCommandServer &server) :
        ZergCommand(ExecuteCommand::COMMAND_ID, server) {}

zerg_cmd_result_t ExecuteCommand::execute() {
    if (server_.get_state() != ZERG_SERVER_WAIT_FOR_CMD) {
        return ERROR;
    }

    if (server_.write_to_executor(&type_, sizeof(type_)) <= 0) {
        return ERROR;
    }
    server_.set_state(ZERG_SERVER_EXECUTING);

    return OK;
}

GetServerStateCommand::GetServerStateCommand(ZergCommandServer &server) :
        ZergCommand(GetServerStateCommand::COMMAND_ID, server) {}

zerg_cmd_result_t GetServerStateCommand::execute() {
    const std::string name = server_.get_state_string();
    if (server_.write_to_commander(name.c_str(), name.size() + 1) <= 0) {
        std::cout << "Error writing server state to commander" << std::endl;
    }

    return OK;
}