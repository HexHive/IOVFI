//
// Created by derrick on 12/2/18.
//

#ifndef FOSBIN_FOSBINLOGGER_H
#define FOSBIN_FOSBINLOGGER_H

#include <iostream>
#include <boost/log/core.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/expressions.hpp>
#include <boost/interprocess/sync/scoped_lock.hpp>
#include <boost/interprocess/sync/named_mutex.hpp>

namespace logging = boost::log;
namespace ip = boost::interprocess;

namespace fbf {
    class FOSBinLogger {
    public:
        FOSBinLogger();
        void set_system_level(logging::trivial::severity_level level);
        FOSBinLogger& set_level(logging::trivial::severity_level level);

        FOSBinLogger& operator<<(const char* str);
        FOSBinLogger& operator<<(const std::string& str);
        FOSBinLogger& operator<<(const void* p);

        template<typename Number,
                typename = std::enable_if_t<std::is_floating_point<Number>::value ||
                        std::is_integral<Number>::value> >
        FOSBinLogger& operator<<(Number i);

    protected:
        ip::named_mutex mutex_;
        logging::trivial::severity_level level_;
        logging::trivial::severity_level system_level_;

#define write_logger(s)  switch(level_){ \
        case logging::trivial::severity_level::trace: \
            BOOST_LOG_TRIVIAL(trace) << s; \
            break; \
        case logging::trivial::severity_level::debug: \
            BOOST_LOG_TRIVIAL(debug) <<  s; \
            break; \
        case logging::trivial::severity_level::error: \
            BOOST_LOG_TRIVIAL(error) <<  s; \
            break; \
        case logging::trivial::severity_level::fatal: \
            BOOST_LOG_TRIVIAL(fatal) <<  s; \
            break; \
        case logging::trivial::severity_level::warning: \
            BOOST_LOG_TRIVIAL(warning) << s; \
            break; \
        default: /* This shouldn't happen */ break; }
    };
}

fbf::FOSBinLogger logger;

#define LOG_TRACE   logger.set_level(logging::trivial::severity_level::trace)
#define LOG_DEBUG   logger.set_level(logging::trivial::severity_level::debug)
#define LOG_INFO    logger.set_level(logging::trivial::severity_level::info)
#define LOG_WARN    logger.set_level(logging::trivial::severity_level::warning)
#define LOG_ERR     logger.set_level(logging::trivial::severity_level::error)
#define LOG_FATAL   logger.set_level(logging::trivial::severity_level::fatal)


#endif //FOSBIN_FOSBINLOGGER_H
