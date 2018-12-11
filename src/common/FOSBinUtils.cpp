//
// Created by derrick on 12/3/18.
//

#include <FOSBinUtils.h>

pid_t fosbin_fork() {
    fbf::FOSBinLogger::Instance().flush();
    pid_t pid = fork();
    if(pid == 0) {
        fbf::FOSBinLogger::Initialize();
    }
    return pid;
}