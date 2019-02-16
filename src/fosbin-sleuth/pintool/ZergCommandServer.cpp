//
// Created by derrick on 2/14/19.
//

#include "ZergCommandServer.h"
#include "ZergCommand.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

ZergCommandServer::ZergCommandServer(struct PinSystem *system) :
        current_state_(ZERG_SERVER_START),
        in_pipe_(-1),
        out_pipe_(-1),
        exe_thread_id_(INVALID_THREADID),
        system_(system) {
    in_pipe_ = open(system->pipe_in.c_str(), 0, O_RDONLY);
    out_pipe_ = open(system->pipe_out.c_str(), 0, O_WRONLY);

    if (in_pipe_ < 0) {
        std::cout << "Could not open in pipe at " << system->pipe_in << std::endl;
        PIN_ExitApplication(1);
    }
    if (out_pipe_ < 0) {
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
        if (read(in_pipe_, (char *) &cmd_type, sizeof(cmd_type)) < 0) {
            log("Error reading pipe");
            continue;
        }
        ZergCommand *cmd = ZergCommand::create(cmd_type, *this);
        if (cmd) {
            zerg_cmd_result_t result = cmd->execute();
            if (write(out_pipe_, (char *) &result, sizeof(result)) < 0) {
                log("Error writing to pipe");
            }
            delete cmd;
        } else {
            write(out_pipe_, (char *) &InvalidCommand::COMMAND_ID, sizeof(InvalidCommand::COMMAND_ID));
        }
    }
}

void ZergCommandServer::stop() {
    current_state_ = ZERG_SERVER_EXIT;
    if (in_pipe_ > 0) {
        close(in_pipe_);
    }

    if (out_pipe_ > 0) {
        close(out_pipe_);
    }
}

void ZergCommandServer::log(const std::string &msg) {
    std::cout << msg << std::endl;
}