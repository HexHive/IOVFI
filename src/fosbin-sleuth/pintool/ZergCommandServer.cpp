//
// Created by derrick on 2/14/19.
//

#include "ZergCommandServer.h"

ZergCommandServer::ZergCommandServer(struct PinSystem *system) :
        current_state_(ZERG_SERVER_START),
        in_pipe_(system->pipe_in.c_str(), std::ifstream::binary | std::ios_base::in),
        out_pipe_(system->pipe_out.c_str(), std::ofstream::binary | std::ios_base::out),
        exe_thread_id_(INVALID_THREADID),
        system_(system) {
    if (!in_pipe_) {
        std::cout << "Could not open in pipe at " << system->pipe_in << std::endl;
        PIN_ExitApplication(1);
    }
    if (!out_pipe_) {
        std::cout << "Could not open out pipe at " << system->pipe_out << std::endl;
        PIN_ExitApplication(1);
    }
}

ZergCommandServer::~ZergCommandServer() {
    stop();
}

void ZergCommandServer::set_exe_thread(THREADID exe_thread_id) {
    exe_thread_id_ = exe_thread_id;
}

zerg_server_state_t ZergCommandServer::get_state() {
    return current_state_;
}

void ZergCommandServer::start() {
    std::cout << "Starting ZergCommandServer" << std::endl;
    zerg_cmd_t cmd_type;
    TRACE_AddInstrumentFunction(system_->trace_func, nullptr);

    current_state_ = ZERG_SERVER_WAIT_FOR_TARGET;
    while (current_state_ != ZERG_SERVER_EXIT) {
        in_pipe_.read((char *) &cmd_type, sizeof(cmd_type));
        ZergCommand *cmd = ZergCommand::create(cmd_type, *this);
        if (cmd) {
            zerg_cmd_result_t result = cmd->execute();
            out_pipe_.write((char *) &result, sizeof(result));
            delete cmd;
        } else {
            out_pipe_.write((char *) &InvalidCommand::COMMAND_ID, sizeof(InvalidCommand::COMMAND_ID));
        }
    }
}

void ZergCommandServer::stop() {
    current_state_ = ZERG_SERVER_EXIT;
    if (in_pipe_) {
        in_pipe_.close();
    }

    if (out_pipe_) {
        out_pipe_.close();
    }
}

void ZergCommandServer::log(std::string &msg) {
    std::cout << msg << std::endl;
}