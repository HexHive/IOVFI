//
// Created by derrick on 2/14/19.
//

#include "ZergCommandServer.h"
#include "ZergCommand.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

ZergCommandServer::ZergCommandServer(int internal_w, int internal_r, std::string cmd_in_name, std::string
cmd_out_name, const std::string &log_name)
        :
        current_state_(ZERG_SERVER_START),
        cmd_in_name_(cmd_in_name), cmd_out_name_(cmd_out_name),
        internal_w_fd(internal_w), internal_r_fd(internal_r),
        cmd_w_fd(-1), cmd_r_fd(-1), logger_() {
    FD_ZERO(&fd_w_set_);
    FD_ZERO(&fd_r_set_);
    std::string logger_name = log_name;
    if (log_name.empty()) {
        std::stringstream tmp;
        tmp << PIN_GetPid() << ".cmd.log";
        logger_name = tmp.str();
    }
    logger_.open(logger_name.c_str(), std::ios::app);
}

ZergCommandServer::~ZergCommandServer() {
    stop();
}

zerg_server_state_t ZergCommandServer::get_state() {
    return current_state_;
}

bool ZergCommandServer::is_valid_transition(zerg_server_state_t trans) {
    if (trans == current_state_ || trans == ZERG_SERVER_EXIT) {
        return true;
    }

    switch (current_state_) {
        case ZERG_SERVER_START:
            return (trans == ZERG_SERVER_WAIT_FOR_TARGET);
        case ZERG_SERVER_WAIT_FOR_TARGET:
            return (trans == ZERG_SERVER_WAIT_FOR_CMD);
        case ZERG_SERVER_WAIT_FOR_CMD:
            return (trans == ZERG_SERVER_FUZZING ||
                    trans == ZERG_SERVER_SETTING_CTX);
        case ZERG_SERVER_FUZZING:
            return (trans == ZERG_SERVER_WAIT_FOR_CMD ||
                    trans == ZERG_SERVER_WAITING_TO_EXE);
        case ZERG_SERVER_SETTING_CTX:
            return (trans == ZERG_SERVER_WAIT_FOR_CMD ||
                    trans == ZERG_SERVER_WAITING_TO_EXE);
        case ZERG_SERVER_WAITING_TO_EXE:
            return (trans == ZERG_SERVER_WAIT_FOR_CMD ||
                    trans == ZERG_SERVER_EXECUTING);
        case ZERG_SERVER_EXECUTING:
            return (trans == ZERG_SERVER_WAIT_FOR_CMD ||
                    trans == ZERG_SERVER_REPORT_ERROR);
        case ZERG_SERVER_REPORT_ERROR:
            return (trans == ZERG_SERVER_WAIT_FOR_CMD);
        default:
            return false;
    }
}

bool ZergCommandServer::set_state(zerg_server_state_t state) {
    if (is_valid_transition(state)) {
        current_state_ = state;
        return true;
    }
    return false;
}

bool ZergCommandServer::is_valid_message_for_state(ZergMessage *msg) {
    if (!msg) {
        return false;
    }

    /* We always want to be able to exit */
    if (msg->type() == ZMSG_EXIT) {
        return true;
    }

    switch (current_state_) {
        case ZERG_SERVER_WAIT_FOR_TARGET:
            return (msg->type() == ZMSG_SET_TGT);
        case ZERG_SERVER_WAIT_FOR_CMD:
            return (msg->type() == ZMSG_SET_TGT ||
                    msg->type() == ZMSG_SET_SO_TGT ||
                    msg->type() == ZMSG_FUZZ ||
                    msg->type() == ZMSG_SET_CTX ||
                    msg->type() == ZMSG_RESET);
        case ZERG_SERVER_FUZZING:
            return (msg->type() == ZMSG_RESET);
        case ZERG_SERVER_EXECUTING:
            return (msg->type() == ZMSG_RESET);
        case ZERG_SERVER_REPORT_ERROR:
            return (msg->type() == ZMSG_RESET);
        case ZERG_SERVER_SETTING_CTX:
            return (msg->type() == ZMSG_RESET);
        case ZERG_SERVER_WAITING_TO_EXE:
            return (msg->type() == ZMSG_RESET ||
                    msg->type() == ZMSG_EXECUTE);
        default:
            return false;
    }
}

ZergCommand *ZergCommandServer::read_commander_command() {
    ZergMessage *msg = read_from_commander();
    ZergCommand *result;
    if (!is_valid_message_for_state(msg)) {
        if (msg) {
            logger_ << "Invalid message for state " << get_state_string(current_state_) << ": " << msg->str() <<
                    std::endl;
        } else {
            logger_ << "Null message" << std::endl;
        }
        result = new InvalidCommand(*msg, *this);
    } else {
        result = ZergCommand::create(*msg, *this);
    }

    delete msg;
    return result;
}

void ZergCommandServer::handle_command() {
    ZergCommand *zergCommand = read_commander_command();
    if (zergCommand) {
        ZergMessage msg(ZMSG_ACK);
        write_to_commander(msg);
        zergCommand->execute();
        delete zergCommand;
    } else {
        ZergMessage msg(ZMSG_FAIL);
        write_to_commander(msg);
    }
}

void ZergCommandServer::start() {
    cmd_r_fd = open(cmd_in_name_.c_str(), O_RDONLY);
    if (cmd_r_fd <= 0) {
        logger_ << "Command Server could not open " << cmd_in_name_ << std::endl;
        current_state_ = ZERG_SERVER_INVALID;
        return;
    }
    cmd_w_fd = open(cmd_out_name_.c_str(), O_WRONLY);
    if (cmd_w_fd <= 0) {
        logger_ << "Command Server could not open " << cmd_out_name_ << std::endl;
        current_state_ = ZERG_SERVER_INVALID;
        return;
    }

    log("Starting ZergCommandServer");
    ZergMessage *ready = read_from_executor();
    if (ready && ready->type() == ZMSG_READY) {
        write_to_commander(*ready);
        delete ready;
    } else {
        log("Invalid ready message from executor");
        current_state_ = ZERG_SERVER_INVALID;
        if (ready) {
            delete ready;
        }
        return;
    }
    log("Ready msg sent");

    current_state_ = ZERG_SERVER_WAIT_FOR_TARGET;
    while (current_state_ != ZERG_SERVER_EXIT) {
        FD_ZERO(&fd_r_set_);
        FD_SET(cmd_r_fd, &fd_r_set_);
        FD_SET(internal_r_fd, &fd_r_set_);
        logger_ << "ZergCommandServer waiting for command. Current State: " << get_state_string(current_state_)
                << std::endl;
        if (select(FD_SETSIZE, &fd_r_set_, nullptr, nullptr, nullptr) > 0) {
            if (FD_ISSET(cmd_r_fd, &fd_r_set_)) {
                handle_command();
            }
            if (FD_ISSET(internal_r_fd, &fd_r_set_)) {
                handle_executor_msg();
            }
        } else if (errno == EINTR) {
            current_state_ = ZERG_SERVER_EXIT;
            logger_ << "Command Server Detected Interrupt" << std::endl;
        }
    }
}

void ZergCommandServer::stop() {
    log("Stopping server");
    set_state(ZERG_SERVER_EXIT);
}

void ZergCommandServer::log(const std::string &msg) {
    logger_ << msg << std::endl;
}

size_t ZergCommandServer::write_to_commander(const ZergMessage &msg) {
    size_t written = msg.write_to_fd(cmd_w_fd);
    if (written == 0) {
        log("Writing to commander failed");
    } else {
        std::stringstream logmsg;
        logmsg << "Wrote " << written << " bytes to commander in " << msg.str() << " msg";
        log(logmsg.str());
    }
    return written;
}

size_t ZergCommandServer::write_to_executor(const ZergMessage &msg) {
    size_t result = msg.write_to_fd(internal_w_fd);
    return result;
}

ZergMessage *ZergCommandServer::read_from_commander() {
    ZergMessage *result = new ZergMessage();
    if (result->read_from_fd(cmd_r_fd) == 0) {
        log("Error reading from command pipe");
        stop();
        PIN_ExitApplication(1);
    } else {
        std::stringstream msg;
        msg << "Read " << result->str() << " msg with " << result->size() << " bytes from commander";
        log(msg.str());
    }
    return result;
}

ZergMessage *ZergCommandServer::read_from_executor() {
    ZergMessage *result = new ZergMessage();
    if (result->read_from_fd(internal_r_fd) == 0) {
        log("Error reading from executor pipe");
        stop();
        PIN_ExitApplication(1);
    } else {
        std::stringstream msg;
        msg << "Read " << result->str() << " msg with " << result->size() << " bytes from executor";
        log(msg.str());
    }
    return result;
}

void ZergCommandServer::handle_executor_msg() {
    ZergMessage *msg = read_from_executor();
    zerg_server_state_t next_state = current_state_;
    if (msg->type() == ZMSG_OK) {
        log("Received OK from executor");
        write_to_commander(*msg);
        switch (current_state_) {
            case ZERG_SERVER_WAIT_FOR_TARGET:
                next_state = ZERG_SERVER_WAIT_FOR_CMD;
                break;
            case ZERG_SERVER_FUZZING:
            case ZERG_SERVER_SETTING_CTX:
                next_state = ZERG_SERVER_WAITING_TO_EXE;
                break;
            case ZERG_SERVER_EXECUTING:
                next_state = ZERG_SERVER_WAIT_FOR_CMD;
                break;
            default:
                /* Deliberately empty */
                break;
        }
    } else if (msg->type() == ZMSG_FAIL) {
        log("Received FAIL from executor");
        write_to_commander(*msg);
        switch (current_state_) {
            case ZERG_SERVER_WAIT_FOR_TARGET:
                next_state = ZERG_SERVER_WAIT_FOR_TARGET;
                break;
            case ZERG_SERVER_FUZZING:
            case ZERG_SERVER_SETTING_CTX:
                next_state = ZERG_SERVER_WAIT_FOR_CMD;
                break;
            case ZERG_SERVER_EXECUTING:
                next_state = ZERG_SERVER_REPORT_ERROR;
                break;
            default:
                /* Deliberately empty */
                break;
        }
    } else {
        log("Invalid message from executor");
    }

    if (!set_state(next_state)) {
        std::stringstream ss;
        ss << "Invalid state transition: "
           << get_state_string(current_state_)
           << " -> "
           << get_state_string(next_state);
        log(ss.str());
    }
}

const std::string ZergCommandServer::get_state_string(zerg_server_state_t state) {
    switch (state) {
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
        case ZERG_SERVER_REPORT_ERROR:
            return std::string("ZERG_SERVER_REPORT_ERROR");
        case ZERG_SERVER_SETTING_CTX:
            return std::string("ZERG_SERVER_SETTING_CTX");
        case ZERG_SERVER_WAITING_TO_EXE:
            return std::string("ZERG_SERVER_WAITING_TO_EXE");
        case ZERG_SERVER_INVALID:
            return std::string("ZERG_SERVER_INVALID");
        default:
            return std::string("UNKNOWN");
    }
}