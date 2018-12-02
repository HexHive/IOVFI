//
// Created by derrick on 12/2/18.
//

#include <FOSBinLogger.h>

#include "FOSBinLogger.h"

fbf::FOSBinLogger::FOSBinLogger() :
    level_(logging::trivial::severity_level::trace),
    mutex_(ip::open_or_create, "fosbin-logger")
{

}

fbf::FOSBinLogger &fbf::FOSBinLogger::set_level(logging::trivial::severity_level level) {
    level_ = level;
    return *this;
}

void fbf::FOSBinLogger::operator<<(std::ostream &o) {
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
}
