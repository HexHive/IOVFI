//
// Created by derrick on 12/2/18.
//

#include <FOSBinLogger.h>
#include <boost/interprocess/shared_memory_object.hpp>
#include <boost/interprocess/mapped_region.hpp>
#include <signal.h>

const char *fbf::FOSBinLogger::LOGGER_NAME = "fosbin-logger";
const char *fbf::FOSBinLogger::MUTEX_NAME = "fosbin-logger-mutex";

static fbf::FOSBinLogger* instance;
static ip::shared_memory_object shm;
static ip::mapped_region region;

fbf::FOSBinLogger &fbf::FOSBinLogger::Instance() {
    if(instance == nullptr) {
        ip::shared_memory_object::remove(LOGGER_NAME);
        ip::named_mutex::remove(MUTEX_NAME);

        shm = ip::shared_memory_object(ip::create_only, LOGGER_NAME, ip::read_write);
        shm.truncate(sizeof(fbf::FOSBinLogger));
        region = ip::mapped_region(shm, ip::read_write);
        void* addr = region.get_address();
        instance = new (addr) fbf::FOSBinLogger();
    }

    return *instance;
}

void fbf::FOSBinLogger::Initialize() {
    shm = ip::shared_memory_object(ip::open_or_create, LOGGER_NAME, ip::read_write);
    region = ip::mapped_region(shm, ip::read_write);
    void* addr = region.get_address();
    instance = static_cast<fbf::FOSBinLogger*>(addr);
}

fbf::FOSBinLogger::FOSBinLogger() :
        mutex_(ip::create_only, MUTEX_NAME)
{ }

fbf::FOSBinLogger::~FOSBinLogger() {
//    ip::shared_memory_object::remove(LOGGER_NAME);
    //ip::named_mutex::remove(MUTEX_NAME);
}

void fbf::FOSBinLogger::set_log_level(logging::trivial::severity_level level) {
    system_level_ = level;
}

void fbf::FOSBinLogger::write_message(fbf::log_message &msg) {
    if (msg.get_message().empty() || system_level_ > msg.get_severity()) {
        return;
    }

    boost::posix_time::ptime abs_time = ip::microsec_clock::universal_time() + boost::posix_time::milliseconds(150);
    ip::scoped_lock<ip::named_mutex> lock(mutex_, abs_time);
    while(!lock.owns()) {
        ip::named_mutex::remove(MUTEX_NAME);
        kill(curr_pid, SIGKILL);
        abs_time = ip::microsec_clock::universal_time() + boost::posix_time::milliseconds(150);
        lock.timed_lock(abs_time);
    }

    curr_pid = getpid();
    switch (msg.get_severity()) {
        case logging::trivial::severity_level::trace:
            std::cout << "[trace]: " << msg.get_message() << std::endl;
            break;
        case logging::trivial::severity_level::debug:
            std::cout << "[debug]: " << msg.get_message() << std::endl;
            break;
        case logging::trivial::severity_level::error:
            std::cout << "[error]: " << msg.get_message() << std::endl;
            break;
        case logging::trivial::severity_level::fatal:
            std::cout << "[fatal]: " << msg.get_message() << std::endl;
            break;
        case logging::trivial::severity_level::warning:
            std::cout << "[warning]: " << msg.get_message() << std::endl;
            break;
        default:
            /* This shouldn't happen */
            break;
    }
}

void fbf::FOSBinLogger::flush() {
//    BOOST_LOG_TRIVIAL(trace) << std::flush;
//    BOOST_LOG_TRIVIAL(debug) << std::flush;
//    BOOST_LOG_TRIVIAL(error) << std::flush;
//    BOOST_LOG_TRIVIAL(fatal) << std::flush;
//    BOOST_LOG_TRIVIAL(warning) << std::flush;
}

fbf::log_message &fbf::log_message::operator<<(const char *str) {
    buffer_ << str;
    return *this;
}

fbf::log_message &fbf::log_message::operator<<(const std::string &str) {
    buffer_ << str;
    return *this;
}

fbf::log_message &fbf::log_message::operator<<(const void *p) {
    buffer_ << "0x" << std::hex << p << std::dec;
    return *this;
}

fbf::log_message &fbf::log_message::operator<<(uintptr_t p) {
    buffer_ << "0x" << std::hex << p << std::dec;
    return *this;
}

fbf::log_message::log_message(logging::trivial::severity_level level) :
        level_(level)
{ buffer_ << "(pid " << getpid() << ") "; }

fbf::log_message::~log_message() {
    try {
        fbf::FOSBinLogger::Instance().write_message(*this);
    } catch(boost::interprocess::lock_exception& e) {
        std::cerr << "ERROR writing " << get_message() << ": " << e.what() << std::endl;
    }
}

std::string fbf::log_message::get_message() {
    return buffer_.str();
}

logging::trivial::severity_level fbf::log_message::get_severity() {
    return level_;
}
