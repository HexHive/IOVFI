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
    ZERG_SERVER_EXIT
} zerg_server_state_t;

class ZergCommandServer {
public:
    ZergCommandServer(int internal_w, int internal_r, int cmd_w, int cmd_r);

    ~ZergCommandServer();

    void start();

    void stop();

    zerg_server_state_t get_state();

    int write_to_commander(const char *msg, size_t size);

    int write_to_executor(const char *msg, size_t size);

    int read_from_commander(char *buf, size_t size);

    int read_from_executor(char *buf, size_t size);

protected:
    zerg_server_state_t current_state_;

    void log(const std::string &msg);

    void handle_command();

    void handle_executor_msg();

    int internal_w_fd, internal_r_fd, cmd_w_fd, cmd_r_fd;
    fd_set fd_w_set_, fd_r_set_;
};

#include "ZergCommandServer.cpp"

#endif //FOSBIN_ZERGCOMMANDSERVER_H
