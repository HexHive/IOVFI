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

struct PinSystem {
    RTN *target;
    AFUNPTR fuzz_round_end;
    std::string pipe_in;
    std::string pipe_out;
    TRACE_INSTRUMENT_CALLBACK trace_func;
};

class ZergCommandServer {
    friend class ZergCommand;

public:
    ZergCommandServer(struct PinSystem *system);

    ~ZergCommandServer();

    void start();

    void stop();

    zerg_server_state_t get_state();

    void set_exe_thread(THREADID exe_thread_id);

protected:
    zerg_server_state_t current_state_;
    std::ifstream in_pipe_;
    std::ofstream out_pipe_;
    THREADID exe_thread_id_;
    PinSystem *system_;

    void log(std::string &msg);
};

#include "ZergCommandServer.cpp"

#endif //FOSBIN_ZERGCOMMANDSERVER_H
