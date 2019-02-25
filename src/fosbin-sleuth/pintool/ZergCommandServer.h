//
// Created by derrick on 2/14/19.
//

#ifndef FOSBIN_ZERGCOMMANDSERVER_H
#define FOSBIN_ZERGCOMMANDSERVER_H

#include <fstream>
#include <iostream>
#include "ZergCommand.h"

typedef enum zerg_server_state {
    ZERG_SERVER_INVALID,
    ZERG_SERVER_START,
    ZERG_SERVER_WAIT_FOR_TARGET,
    ZERG_SERVER_WAIT_FOR_CMD,
    ZERG_SERVER_FUZZING,
    ZERG_SERVER_EXECUTING,
    ZERG_SERVER_EXIT,
    ZERG_SERVER_REPORT_ERROR,
    ZERG_SERVER_SETTING_CTX,
    ZERG_SERVER_WAITING_TO_EXE
} zerg_server_state_t;

class ZergCommandServer {
public:
    ZergCommandServer(int internal_w, int internal_r, std::string cmd_in_name, std::string cmd_out_name, const
    std::string &log_name);

    ~ZergCommandServer();

    void start();

    void stop();

    zerg_server_state_t get_state();

    bool set_state(zerg_server_state_t state);

    size_t write_to_commander(const ZergMessage &msg);

    size_t write_to_executor(const ZergMessage &msg);

    ZergMessage *read_from_commander();

    ZergMessage *read_from_executor();

    const std::string get_state_string(zerg_server_state_t state);

    void log(const std::string &msg);

protected:
    zerg_server_state_t current_state_;

    void handle_command();

    void handle_executor_msg();

    ZergCommand *read_commander_command();

    bool is_valid_message_for_state(ZergMessage *msg);

    bool is_valid_transition(zerg_server_state_t trans);

    std::string cmd_in_name_, cmd_out_name_;

    int internal_w_fd, internal_r_fd, cmd_w_fd, cmd_r_fd;
    fd_set fd_w_set_, fd_r_set_;

    std::ofstream logger_;
};

#include "ZergCommandServer.cpp"

#endif //FOSBIN_ZERGCOMMANDSERVER_H
