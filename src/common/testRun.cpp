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

fbf::TestRun::TestRun(std::shared_ptr<fbf::ITestCase> test, uintptr_t offset, bool fork) :
    test_(test),
    fork_(fork),
    test_has_run_(false),
    offset_(offset),
    result_(std::numeric_limits<int>::max()) { pipe[0] = 0; pipe[1] = 0; }

fbf::TestRun::~TestRun() = default;

const unsigned int fbf::TestRun::TIMEOUT = 2;

static void sig_handler(int signum) {
    exit(fbf::ITestCase::FAIL);
}

void fbf::TestRun::set_signals() {
    /* Change process group ID to avoid ending the parent process if kill* is called */
    signal(SIGALRM, sig_handler);
    //signal(SIGINT, sig_handler);
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

    LOG_INFO << "Running test "
        << get_test_name() 
        << " on offset " << offset_;
    test_->set_location(offset_);
    if(fork_) {
        open_pipe();
        pid_t pid = fork();
        if (pid < 0) {
            close_pipe();
            throw std::runtime_error("Failed to fork");
        } else if (pid == 0) {
            set_signals();
            int result = test_->run_test();
            write_to_parent();
            close_pipe();
            exit(result);
        } else {
            result_ = determine_result(pid);
        }
    } else {
        result_ = test_->run_test();
    }
}

test_result_t fbf::TestRun::determine_result(pid_t child) {
    waitpid(child, &pid_status_, 0);
    read_from_child();
    close_pipe();

    if (WIFSIGNALED(pid_status_)) {
        /* SIGILL, SIGSEGV, etc. caused the child to stop...not what we are looking for */
        return fbf::ITestCase::FAIL;
    } else if(WIFEXITED(pid_status_)) {
        return (WEXITSTATUS(pid_status_) == fbf::ITestCase::PASS ?
            fbf::ITestCase::PASS :
            fbf::ITestCase::NON_CRASHING);
    } else {
        std::string msg = "Unexpected child exit status: ";
        msg += pid_status_;
        throw std::runtime_error(msg.c_str());
    }
}

void fbf::TestRun::write_to_parent() {
/* TODO: Implement me */
}

void fbf::TestRun::read_from_child() {
/* TODO: Implement me */

}

void fbf::TestRun::open_pipe() {
    /* TODO: Implement me */

}

void fbf::TestRun::close_pipe() {
/* TODO: Implement me */

}

uint64_t fbf::TestRun::get_execution_result() {
    return execution_result_;
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
        << ((result_ == fbf::ITestCase::PASS) ? "positive -- " : "negative -- ");

    test_->output_result(out);
    out << std::endl;
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

bool fbf::TestRun::test_crashed() {
    return WIFSIGNALED(pid_status_) != 0;
}

uintptr_t fbf::TestRun::get_location() {
    return test_->get_location();
}
