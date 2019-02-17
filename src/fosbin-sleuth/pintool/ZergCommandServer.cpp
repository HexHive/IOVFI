//
// Created by derrick on 2/14/19.
//

#include "ZergCommandServer.h"
#include "ZergCommand.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

ZergCommandServer::ZergCommandServer(int internal_w, int internal_r, int cmd_w, int cmd_r) :
        current_state_(ZERG_SERVER_START),
        internal_w_fd(internal_w), internal_r_fd(internal_r),
        cmd_w_fd(cmd_w), cmd_r_fd(cmd_r) {
    FD_ZERO(&fd_w_set_);
    FD_ZERO(&fd_r_set_);

    FD_SET(internal_w, &fd_w_set_);
    FD_SET(cmd_w, &fd_w_set_);
    FD_SET(internal_r, &fd_r_set_);
    FD_SET(cmd_r, &fd_r_set_);
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

void ZergCommandServer::handle_command() {
    zerg_cmd_t cmd;
    zerg_cmd_result_t result = ERROR;
    if (read(cmd_r_fd, (char *) &cmd, sizeof(cmd)) < 0) {
        log("Error reading from command pipe");
    } else {
        zerg_cmd_result_t result;
        ZergCommand *zergCommand = ZergCommand::create(cmd, *this);
        if (zergCommand) {
            result = zergCommand->execute();
            delete zergCommand;
        }
    }
    write_to_commander((const char *) &result, sizeof(result));
}

void ZergCommandServer::start() {
    std::cout << "Starting ZergCommandServer" << std::endl;
    zerg_cmd_t cmd_type;

    current_state_ = ZERG_SERVER_WAIT_FOR_TARGET;
    while (current_state_ != ZERG_SERVER_EXIT) {
        if (select(FD_SETSIZE, &fd_r_set_, &fd_w_set_, NULL, NULL) > 0) {
            if (FD_ISSET(&fd_r_set, cmd_r_fd)) {
                handle_command();
            }
            if (FD_ISSET(&fd_r_set, internal_r_fd)) {
                handle_executor_msg();
            }
        } else if (errno == EINTR) {
            current_state_ = ZERG_SERVER_EXIT;
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