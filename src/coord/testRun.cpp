//
// Created by derrick on 7/8/18.
//

#include <testRun.h>
#include <memory>
#include <iostream>
#include <cstring>
#include <unistd.h>
#include <sys/wait.h>

fbf::TestRun::TestRun(std::shared_ptr<fbf::FunctionIdentifier> test, uintptr_t offset) :
    test_(test),
    test_has_run_(false),
    offset_(offset),
    result_(std::numeric_limits<int>::max()) { }

fbf::TestRun::~TestRun() = default;

const unsigned int fbf::TestRun::TIMEOUT = 2;

static void alarm_handler(int signum) {
    exit(fbf::FunctionIdentifier::FAIL);
}

void fbf::TestRun::set_signals() {
    signal(SIGALRM, alarm_handler);
    alarm(TIMEOUT);
}

void fbf::TestRun::run_test() {
    if(test_has_run_) {
        return;
    }
    test_has_run_ = true;

    pid_t pid = fork();
    if(pid < 0) {
        throw std::runtime_error("Failed to fork");
    } else if(pid == 0) {
        set_signals();
        exit(test_->run_test());
    } else {
        result_ = determine_result(pid);
    }
}

test_result_t fbf::TestRun::determine_result(pid_t child) {
    int status;
    waitpid(child, &status, 0);
    if(WIFSIGNALED(status)) {
        /* SIGILL, SIGSEGV, etc. caused the child to stop...not what we are looking for */
        return fbf::FunctionIdentifier::FAIL;
    } else if(WIFEXITED(status)) {
        return (WEXITSTATUS(status) == 255 ?
            fbf::FunctionIdentifier::PASS :
            fbf::FunctionIdentifier::FAIL);
    } else {
        std::string msg = "Unexpected child exit status: ";
        msg += status;
        throw std::runtime_error(msg.c_str());
    }
}

void fbf::TestRun::output_results(std::ostream &out) {
    /* TODO: Implement a better version of this */
    if(!test_has_run_) {
        run_test();
    }

    out << "Result for "
        << test_->getFunctionName()
        << " at offset 0x"
        << std::hex
        << offset_
        << ": "
        << ((result_ == fbf::FunctionIdentifier::PASS) ? "positive" : "negative")
        << std::endl;
}

test_result_t fbf::TestRun::get_result() {
    if(!test_has_run_) {
        run_test();
    }

    return result_;
}
