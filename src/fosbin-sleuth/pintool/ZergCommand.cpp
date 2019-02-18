//
// Created by derrick on 2/14/19.
//

#include "ZergCommand.h"
#include "ZergCommandServer.h"

const zerg_cmd_t SetTargetCommand::COMMAND_ID = 1;
const zerg_cmd_t InvalidCommand::COMMAND_ID = 2;
const zerg_cmd_t ExitCommand::COMMAND_ID = 3;

ZergCommand::ZergCommand(zerg_cmd_t type, ZergCommandServer &server) :
        server_(server),
        type_(type) {}

ZergCommand::~ZergCommand() {}

ZergCommand *ZergCommand::create(zerg_cmd_t type, ZergCommandServer &server) {
    switch (type) {
        case SetTargetCommand::COMMAND_ID:
            return new SetTargetCommand(server);
        default:
            return new InvalidCommand(server);
    }
}

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
    if (new_target_ == 0) {
        return ERROR;
    }

    server_.write_to_executor((char *) &SetTargetCommand::COMMAND_ID, sizeof(SetTargetCommand::COMMAND_ID));
    server_.write_to_executor((char *) &new_target_, sizeof(new_target_));

    return OK;
}

InvalidCommand::InvalidCommand(ZergCommandServer &server) :
        ZergCommand(InvalidCommand::COMMAND_ID, server) {}

zerg_cmd_result_t InvalidCommand::execute() { return ERROR; }

ExitCommand::ExitCommand(ZergCommandServer &server) :
        ZergCommand(ExitCommand::COMMAND_ID, server) {}

zerg_cmd_result_t ExitCommand::execute() {
    server_.stop();
    return OK;
}