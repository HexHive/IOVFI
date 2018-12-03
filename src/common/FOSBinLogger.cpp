//
// Created by derrick on 12/2/18.
//

#include <FOSBinLogger.h>
#include <iomanip>

fbf::FOSBinLogger::FOSBinLogger() :
    level_(logging::trivial::severity_level::trace),
    system_level_(level_),
    mutex_(ip::open_or_create, "fosbin-logger")
{

}

fbf::FOSBinLogger &fbf::FOSBinLogger::set_level(logging::trivial::severity_level level) {
    level_ = level;
    return *this;
}

<<<<<<< HEAD
fbf::FOSBinLogger& fbf::FOSBinLogger::operator<<(const std::ostream &o) {
    ip::scoped_lock<ip::named_mutex> log_lock(mutex_);
    switch(level_){
        case logging::trivial::severity_level::trace:
            BOOST_LOG_TRIVIAL(trace) << o;
            break;
        case logging::trivial::severity_level::debug:
            BOOST_LOG_TRIVIAL(debug) << o;
            break;
        case logging::trivial::severity_level::error:
            BOOST_LOG_TRIVIAL(error) << o;
            break;
        case logging::trivial::severity_level::fatal:
            BOOST_LOG_TRIVIAL(fatal) << o;
            break;
        case logging::trivial::severity_level::warning:
            BOOST_LOG_TRIVIAL(warning) << o;
            break;
        default:
            /* This shouldn't happen */
            break;
    }
    log_lock.unlock();
    return *this;
}

void fbf::FOSBinLogger::set_system_level(logging::trivial::severity_level level) {
    system_level_ = level;
}

fbf::FOSBinLogger& fbf::FOSBinLogger::operator<<(const char *str) {
    std::stringstream ss;
    ss << str;
    write_logger(ss.str());
    return *this;
}

fbf::FOSBinLogger& fbf::FOSBinLogger::operator<<(const std::string &str) {
    std::stringstream ss;
    ss << str;
    write_logger(ss.str());
    return *this;
}

template<typename Number, typename>
fbf::FOSBinLogger &fbf::FOSBinLogger::operator<<(Number i) {
    std::stringstream ss;
    if(std::is_floating_point_v<Number>) {
        ss << std::setprecision(std::numeric_limits<Number>::digits10 + 1);
    } else if (typeid(uintptr_t) == typeid(Number)) {
        ss << "0x" << std::hex;
    }

    ss << i;
    write_logger(ss.str());
    return *this;
}

fbf::FOSBinLogger &fbf::FOSBinLogger::operator<<(const void *p) {
    std::stringstream ss;
    ss << "0x" << std::hex << p;
    write_logger(ss.str());
    return *this;
}
