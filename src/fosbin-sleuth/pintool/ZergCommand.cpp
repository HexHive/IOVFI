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
    server_.log(msg.str());
    msg.str(std::string());
}

SetTargetCommand::SetTargetCommand(ZergCommandServer &server) :
        ZergCommand(SetTargetCommand::COMMAND_ID, server),
        new_target_(0) {
    server_.in_pipe_.read((char *) &new_target_, sizeof(new_target_));
    std::stringstream msg;
    msg << "Read in new target 0x" << std::hex << new_target_;
    log(msg);
}

zerg_cmd_result_t SetTargetCommand::execute() {
    if (server_.exe_thread_id_ == INVALID_THREADID) {
        return ERROR;
    }

    PIN_StopApplicationThreads(server_.exe_thread_id_);

    std::stringstream msg;
    msg << "Setting new target to 0x" << std::hex << new_target_;
    log(msg);
    RTN new_target = RTN_FindByAddress(new_target_);
    if (!RTN_Valid(new_target)) {
        msg << "Could not find valid target";
        log(msg);
        return NOT_FOUND;
    }

    msg << "Found target: " << RTN_Name(new_target) << " at 0x" << std::hex << RTN_Address(new_target) << std::endl;
    log(msg);
    msg << "Instrumenting returns...";
    RTN_Open(new_target);
    for (INS ins = RTN_InsHead(new_target); INS_Valid(ins); ins = INS_Next(ins)) {
        if (INS_IsRet(ins)) {
            INS_InsertCall(ins, IPOINT_BEFORE, server_.system_->fuzz_round_end, IARG_CONTEXT, IARG_THREAD_ID, IARG_END);
        }
    }
    INS_InsertCall(RTN_InsTail(new_target), IPOINT_BEFORE, server_.system_->fuzz_round_end, IARG_CONTEXT,
                   IARG_THREAD_ID, IARG_END);
    RTN_Close(new_target);
    msg << "done.";
    log(msg);
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