//
// Created by derrick on 10/10/18.
//
#include <iostream>
#include <commandLineParser.h>
#include <boost/log/sinks/text_file_backend.hpp>
#include <boost/log/utility/setup/file.hpp>
#include <thread>

static void log_range_check(const int log_level) {
    if (log_level < boost::log::trivial::severity_level::trace ||
        log_level > boost::log::trivial::severity_level::fatal) {
        throw std::runtime_error("Invalid log level");
    }
}

extern fbf::FOSBinLogger logger;

fbf::CommandLineParser::CommandLineParser(int argc, char **argv, const char *name) :
        argc_(argc),
        argv_(argv),
        thread_count_(1),
        generic_("Generic Options"),
        positional_(),
        vm_(),
        cmd_parsed_(false),
        name_(name),
        log_path_(),
        log_level_(logging::trivial::info),
        log_level_i_(static_cast<int>(logging::trivial::info)) {
    std::stringstream log_level_msg;
    log_level_msg << "Make logging more or less verbose. Acceptable values are [ " << std::endl;
    for (int val = boost::log::trivial::severity_level::trace;
         val != boost::log::trivial::severity_level::fatal; val++) {
        log_level_msg << val << " (" << static_cast<boost::log::trivial::severity_level>(val) << ") " << std::endl;
    }
    log_level_msg << "]";

    generic_.add_options()
            ("version,v", "Prints version string")
            ("help,h", "Prints this message")
            ("num-threads,t",
             boost::program_options::value<uint32_t>(&thread_count_)->default_value(
                     thread_count_),
             "Number of threads to use")
            ("log", po::value<fs::path>(&log_path_), "/path/to/log/file")
            ("log-level", po::value<int>(&log_level_i_)->default_value(log_level_i_)->notifier(
                    &log_range_check), log_level_msg.str().c_str())
            ("binary-desc,i", po::value<fs::path>()->required(), "/path/to/binary/descriptor");
}

void fbf::CommandLineParser::parse() {
    try {
        positional_.add("binary-desc", -1);
        po::store(po::command_line_parser(argc_, argv_)
                          .options(generic_)
                          .positional(positional_)
                          .run(), vm_);
        po::notify(vm_);
    } catch (const boost::program_options::error &e) {
        LOG_FATAL << e.what();
        print_help();
        exit(1);
    }

    cmd_parsed_ = true;

    if (vm_.count("version")) {
        std::cout << name_
                  << " v. " << FOSBIN_VERSION_MAJOR << "." << FOSBIN_VERSION_MINOR << std::endl;
        exit(0);
    }

    if (vm_.count("help")) {
        print_help();
        exit(0);
    }

    if (thread_count_ < 1) {
        LOG_WARN << "Thread count too low...using 1";
        thread_count_ = 1;
    } else if (thread_count_ > std::thread::hardware_concurrency()) {
        LOG_WARN << "Thread count too high...using " << std::thread::hardware_concurrency();
        thread_count_ = std::thread::hardware_concurrency();
    }

    log_level_ = static_cast<boost::log::trivial::severity_level>(log_level_i_);

    init_logging();
}

size_t fbf::CommandLineParser::count(const char *key) {
    if (!cmd_parsed_) {
        throw std::runtime_error("Command line arguments not parsed");
    }

    return vm_.count(key);
}

uint32_t fbf::CommandLineParser::get_thread_count() {
    return thread_count_;
}

void fbf::CommandLineParser::print_help() {
    std::cout << generic_ << std::endl;
}

const boost::program_options::variable_value &fbf::CommandLineParser::operator[](const std::string &name) const {
    if (!cmd_parsed_) {
        throw std::runtime_error("Command line arguments not parsed");
    }

    return vm_[name];
}

void fbf::CommandLineParser::add_option(const char *name, const char *description) {
    generic_.add_options()(name, description);
}

void fbf::CommandLineParser::add_option(const char *name, const boost::program_options::value_semantic *s) {
    generic_.add_options()(name, s);
}

void fbf::CommandLineParser::add_option(const char *name, const boost::program_options::value_semantic *s,
                                        const char *description) {
    generic_.add_options()(name, s, description);
}

void fbf::CommandLineParser::init_logging() {
FOSBinLogger::Instance().set_log_level(log_level_);
    //    logging::core::get()->set_filter(
//            logging::trivial::severity >= log_level_
//    );
//    if (!log_path_.empty()) {
//        logging::add_file_log(log_path_.c_str());
//    }
}
