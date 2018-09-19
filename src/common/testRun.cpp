//
// Created by derrick on 7/8/18.
//

#include <testRun.h>
#include <memory>
#include <iostream>
#include <cstring>
#include <unistd.h>
#include <sys/wait.h>
#include <sstream>

fbf::TestRun::TestRun(std::shared_ptr<fbf::ITestCase> test, uintptr_t offset) :
    test_(test),
    test_has_run_(false),
    offset_(offset),
    result_(std::numeric_limits<int>::max()) { }

fbf::TestRun::~TestRun() = default;

const unsigned int fbf::TestRun::TIMEOUT = 2;

static void sig_handler(int signum) {
    exit(fbf::ITestCase::FAIL);
}

void fbf::TestRun::set_signals() {
    signal(SIGALRM, sig_handler);
    signal(SIGINT, sig_handler);
    alarm(TIMEOUT);
}

uintptr_t fbf::TestRun::get_offset() {
    return offset_;
}

void fbf::TestRun::run_test() {
    if (test_has_run_) {
        return;
    }
    test_has_run_ = true;

    pid_t pid = fork();
    if (pid < 0) {
        throw std::runtime_error("Failed to fork");
    } else if (pid == 0) {
        set_signals();
        exit(test_->run_test());
    } else {
        result_ = determine_result(pid);
    }
}

test_result_t fbf::TestRun::determine_result(pid_t child) {
    int status;
    waitpid(child, &status, 0);
    if (WIFSIGNALED(status)) {
        /* SIGILL, SIGSEGV, etc. caused the child to stop...not what we are looking for */
        return fbf::ITestCase::FAIL;
    } else if(WIFEXITED(status)) {
        return (WEXITSTATUS(status) == fbf::ITestCase::PASS ?
            fbf::ITestCase::PASS :
            fbf::ITestCase::FAIL);
    } else {
        std::string msg = "Unexpected child exit status: ";
        msg += status;
        throw std::runtime_error(msg.c_str());
    }
}

void fbf::TestRun::output_results(std::ostream &out) {
    /* TODO: Implement a better version of this */
    std::stringstream ss;
    ss << std::hex << offset_;

    if (!test_has_run_) {
        out << "Test for "
        << test_->get_test_name()
        << " at offset 0x"
        << ss.str()
        << " was not run"
        << std::endl;
        return;
    }

    out << "Result for "
        << test_->get_test_name()
        << " at offset 0x"
        << ss.str()
        << " : "
        << ((result_ == fbf::ITestCase::PASS) ? "positive" : "negative")
        << std::endl;
}

test_result_t fbf::TestRun::get_result() {
    if (!test_has_run_) {
        run_test();
    }

    return result_;
}

const std::string fbf::TestRun::get_test_name() {
    return test_->get_test_name();
}
