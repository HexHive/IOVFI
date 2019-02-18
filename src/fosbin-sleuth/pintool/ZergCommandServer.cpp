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

zerg_server_state_t ZergCommandServer::get_state() {
    return current_state_;
}

void ZergCommandServer::handle_command() {
    zerg_cmd_t cmd;
    zerg_cmd_result_t result = ERROR;
    if (read(cmd_r_fd, (char *) &cmd, sizeof(cmd)) < 0) {
        log("Error reading from command pipe");
    } else {
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

    current_state_ = ZERG_SERVER_WAIT_FOR_TARGET;
    while (current_state_ != ZERG_SERVER_EXIT) {
        if (select(FD_SETSIZE, &fd_r_set_, &fd_w_set_, NULL, NULL) > 0) {
            if (FD_ISSET(cmd_r_fd, &fd_r_set_)) {
                handle_command();
            }
            if (FD_ISSET(internal_r_fd, &fd_r_set_)) {
                handle_executor_msg();
            }
        } else if (errno == EINTR) {
            current_state_ = ZERG_SERVER_EXIT;
        }
    }
}

void ZergCommandServer::stop() {
    current_state_ = ZERG_SERVER_EXIT;
    if (internal_w_fd > 0) {
        close(internal_w_fd);
    }

    if (internal_r_fd > 0) {
        close(internal_r_fd);
    }

    if (cmd_w_fd > 0) {
        close(cmd_w_fd);
    }

    if (cmd_r_fd > 0) {
        close(cmd_r_fd);
    }
}

void ZergCommandServer::log(const std::string &msg) {
    std::cout << msg << std::endl;
}

int ZergCommandServer::write_to_commander(const char *msg, size_t size) {
    return write(cmd_w_fd, msg, size);
}

int ZergCommandServer::write_to_executor(const char *msg, size_t size) {
    return write(internal_w_fd, msg, size);
}

int ZergCommandServer::read_from_commander(char *buf, size_t size) {
    return read(cmd_r_fd, buf, size);
}

int ZergCommandServer::read_from_executor(char *buf, size_t size) {
    return read(internal_r_fd, buf, size);
}