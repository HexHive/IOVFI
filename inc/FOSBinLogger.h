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
        FOSBinLogger& set_level(logging::trivial::severity_level level);
        void operator<<(std::ostream& o);

    protected:
        ip::named_mutex mutex_;
        logging::trivial::severity_level level_;
    };
}

fbf::FOSBinLogger logger;

#define LOG_TRACE   logger.set_level(trace) << std::dec
#define LOG_DEBUG   logger.set_level(debug) << std::dec
#define LOG_INFO    logger.set_level(info) << std::dec
#define LOG_WARN    logger.set_level(warning) << std::dec
#define LOG_ERR     logger.set_level(error) << std::dec
#define LOG_FATAL   logger.set_level(fatal) << std::dec


#endif //FOSBIN_FOSBINLOGGER_H
