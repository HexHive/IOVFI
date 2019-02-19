//
// Created by derrick on 2/14/19.
//

#ifndef FOSBIN_ZERGCOMMANDSERVER_H
#define FOSBIN_ZERGCOMMANDSERVER_H

#include <fstream>
#include <iostream>
#include "ZergCommand.h"

typedef enum zerg_server_state {
    ZERG_SERVER_START,
    ZERG_SERVER_WAIT_FOR_TARGET,
    ZERG_SERVER_WAIT_FOR_CMD,
    ZERG_SERVER_FUZZING,
    ZERG_SERVER_EXECUTING,
    ZERG_SERVER_EXIT
} zerg_server_state_t;

class ZergCommandServer {
public:
    ZergCommandServer(int internal_w, int internal_r, std::string cmd_in_name, std::string cmd_out_name);

    ~ZergCommandServer();

    void start();

    void stop();

    zerg_server_state_t get_state();

    void set_state(zerg_server_state_t state);

    int write_to_commander(const void *msg, size_t size);

    int write_to_executor(const void *msg, size_t size);

    int read_from_commander(void *buf, size_t size);

    int read_from_executor(void *buf, size_t size);

    const std::string get_state_string();

protected:
    zerg_server_state_t current_state_;

    void log(const std::string &msg);

    void handle_command();

    void handle_executor_msg();

    std::string cmd_in_name_, cmd_out_name_;

    int internal_w_fd, internal_r_fd, cmd_w_fd, cmd_r_fd;
    fd_set fd_w_set_, fd_r_set_;

};

#include "ZergCommandServer.cpp"

#endif //FOSBIN_ZERGCOMMANDSERVER_H
