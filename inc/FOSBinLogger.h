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
#include <iomanip>

namespace logging = boost::log;
namespace ip = boost::interprocess;

namespace fbf {
    class log_message {
    public:
        log_message(logging::trivial::severity_level level);
        ~log_message();
        log_message& operator<<(const char* str);
        log_message& operator<<(const std::string& str);
        log_message& operator<<(const void* p);
        log_message& operator<<(uintptr_t p);

        template<typename Number,
                typename = std::enable_if_t<std::is_floating_point<Number>::value ||
                                            std::is_integral<Number>::value> >
        log_message& operator<<(Number i);

        std::string get_message();
        logging::trivial::severity_level get_severity();

    protected:
        std::stringstream buffer_;
        logging::trivial::severity_level level_;
    };

    class FOSBinLogger {
    public:
        FOSBinLogger();
        ~FOSBinLogger();

        const static char *LOGGER_NAME, *MUTEX_NAME;

        static FOSBinLogger& Instance();
        static void Initialize();
        void write_message(log_message &msg);
        void flush();
        void set_log_level(logging::trivial::severity_level level);

    protected:
        ip::named_mutex mutex_;
        logging::trivial::severity_level system_level_;
        pid_t curr_pid;
    };

    template<typename Number, typename>
    fbf::log_message &fbf::log_message::operator<<(Number i) {
        if constexpr (std::is_floating_point_v<Number>) {
            buffer_ << std::setprecision(std::numeric_limits<Number>::digits10 + 1);
        }

        buffer_ << i << std::dec;
        return *this;
    }
}

#define LOG_TRACE   fbf::log_message(logging::trivial::severity_level::trace)
#define LOG_DEBUG   fbf::log_message(logging::trivial::severity_level::debug)
#define LOG_INFO    fbf::log_message(logging::trivial::severity_level::info)
#define LOG_WARN    fbf::log_message(logging::trivial::severity_level::warning)
#define LOG_ERR     fbf::log_message(logging::trivial::severity_level::error)
#define LOG_FATAL   fbf::log_message(logging::trivial::severity_level::fatal)


#endif //FOSBIN_FOSBINLOGGER_H
