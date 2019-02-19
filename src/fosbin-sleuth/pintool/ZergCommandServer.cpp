//
// Created by derrick on 2/14/19.
//

#include "ZergCommandServer.h"
#include "ZergCommand.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

ZergCommandServer::ZergCommandServer(int internal_w, int internal_r, std::string cmd_in_name, std::string cmd_out_name)
        :
        current_state_(ZERG_SERVER_START),
        cmd_in_name_(cmd_in_name), cmd_out_name_(cmd_out_name),
        internal_w_fd(internal_w), internal_r_fd(internal_r),
        cmd_w_fd(-1), cmd_r_fd(-1) {
    FD_ZERO(&fd_w_set_);
    FD_ZERO(&fd_r_set_);
}

ZergCommandServer::~ZergCommandServer() {
    stop();
}

zerg_server_state_t ZergCommandServer::get_state() {
    return current_state_;
}

void ZergCommandServer::set_state(zerg_server_state_t state) {
    current_state_ = state;
}

void ZergCommandServer::handle_command() {
    zerg_cmd_t cmd;
    zerg_cmd_result_t result = ERROR;
    read_from_commander(&cmd, sizeof(cmd));
    ZergCommand *zergCommand = ZergCommand::create(cmd, *this);
    if (zergCommand) {
        result = zergCommand->execute();
        delete zergCommand;
    }
    if (write_to_commander(&result, sizeof(result)) <= 0) {
        std::cout << "Error writing to commander: " << strerror(errno) << std::endl;
    }
}

void ZergCommandServer::start() {
    cmd_r_fd = open(cmd_in_name_.c_str(), O_RDONLY);
    if (cmd_r_fd <= 0) {
        std::cout << "Command Server could not open " << cmd_in_name_ << std::endl;
        return;
    }
    cmd_w_fd = open(cmd_out_name_.c_str(), O_WRONLY);
    if (cmd_w_fd <= 0) {
        std::cout << "Command Server could not open " << cmd_out_name_ << std::endl;
        return;
    }

    std::cout << "Starting ZergCommandServer" << std::endl;

    current_state_ = ZERG_SERVER_WAIT_FOR_TARGET;
    while (current_state_ != ZERG_SERVER_EXIT) {
        FD_ZERO(&fd_r_set_);
        FD_SET(cmd_r_fd, &fd_r_set_);
        FD_SET(internal_r_fd, &fd_r_set_);
        std::cout << "ZergCommandServer waiting for command" << std::endl;
        if (select(FD_SETSIZE, &fd_r_set_, nullptr, nullptr, nullptr) > 0) {
            bool reset_connection = false;
            if (FD_ISSET(cmd_r_fd, &fd_r_set_)) {
                handle_command();
                reset_connection = true;
            }
            if (FD_ISSET(internal_r_fd, &fd_r_set_)) {
                handle_executor_msg();
                reset_connection = true;
            }

            if (reset_connection) {
                /* There is some implementation bug in pin that prevents
                 * data from immediately writing to a pipe, even if fflush is used.
                 * This is a hack to get around this bug.
                 * The intent is that if we *ever* write data to the commander
                 * process, close the pipe and reopen it to flush data.
                 */
                close(cmd_w_fd);
                cmd_w_fd = open(cmd_out_name_.c_str(), O_WRONLY);
            }
        } else if (errno == EINTR) {
            current_state_ = ZERG_SERVER_EXIT;
            std::cout << "Command Server Detected Interrupt" << std::endl;
        }
    }
}

void ZergCommandServer::stop() {
    current_state_ = ZERG_SERVER_EXIT;
}

void ZergCommandServer::log(const std::string &msg) {
    std::cout << msg << std::endl;
}

int ZergCommandServer::write_to_commander(const void *msg, size_t size) {
    std::cout << "Writing to commander" << std::endl;
    std::string msg_str((char *) msg);
    std::cout << "Msg: " << msg_str << std::endl;

    int result = write(cmd_w_fd, msg, size);
    if (result < 0) {
        std::cout << "Write failed: " << strerror(errno) << std::endl;
    }
    return result;
}

int ZergCommandServer::write_to_executor(const void *msg, size_t size) {
    int result = write(internal_w_fd, msg, size);
    return result;
}

int ZergCommandServer::read_from_commander(void *buf, size_t size) {
    int bytes_read = read(cmd_r_fd, buf, size);
    if (bytes_read < 0) {
        log("Error reading from command pipe");
        stop();
        PIN_ExitApplication(1);
    } else if (bytes_read == 0) {
        log("Write end of command pipe closed");
        stop();
        PIN_ExitApplication(0);
    }

    return bytes_read;
}

int ZergCommandServer::read_from_executor(void *buf, size_t size) {
    return read(internal_r_fd, buf, size);
}

void ZergCommandServer::handle_executor_msg() {
    std::stringstream ss;
    ss << "Received executor message: ";
    zerg_cmd_result_t msg;
    read(internal_r_fd, &msg, sizeof(msg));
    ss << ZergCommand::result_to_str(msg);
    log(ss.str());
    write_to_commander((char *) &msg, sizeof(msg));
    set_state(ZERG_SERVER_WAIT_FOR_CMD);
}

const std::string ZergCommandServer::get_state_string() {
    switch (get_state()) {
        case ZERG_SERVER_START:
            return std::string("ZERG_SERVER_START");
        case ZERG_SERVER_WAIT_FOR_TARGET:
            return std::string("ZERG_SERVER_WAIT_FOR_TARGET");
        case ZERG_SERVER_WAIT_FOR_CMD:
            return std::string("ZERG_SERVER_WAIT_FOR_CMD");
        case ZERG_SERVER_FUZZING:
            return std::string("ZERG_SERVER_FUZZING");
        case ZERG_SERVER_EXECUTING:
            return std::string("ZERG_SERVER_EXECUTING");
        case ZERG_SERVER_EXIT:
            return std::string("ZERG_SERVER_EXIT");
        default:
            return std::string("UNKNOWN");
    }
}