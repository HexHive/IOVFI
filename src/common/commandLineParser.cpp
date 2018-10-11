//
// Created by derrick on 10/10/18.
//
#include <iostream>
#include <commandLineParser.h>
#include <boost/log/sinks/text_file_backend.hpp>
#include <boost/log/utility/setup/file.hpp>

static void log_range_check(const boost::log::trivial::severity_level log_level) {
    if (log_level < boost::log::trivial::severity_level::trace ||
        log_level > boost::log::trivial::severity_level::fatal) {
        throw std::runtime_error("Invalid log level");
    }
}

fbf::CommandLineParser::CommandLineParser(int argc, char **argv, const char *name) :
        argc_(argc),
        argv_(argv),
        generic_("Generic Options"),
        positional_(),
        vm_(),
        cmd_parsed_(false),
        name_(name),
        log_path_(),
        log_level_(logging::trivial::info) {
    generic_.add_options()
            ("version,v", "Prints version string")
            ("help,h", "Prints this message")
            ("binary-desc,i", po::value<fs::path>()->required(), "/path/to/binary/descriptor")
            ("log", po::value<fs::path>(&log_path_), "/path/to/log/file")
            ("log-level", po::value<logging::trivial::severity_level>(&log_level_)->default_value(log_level_)->notifier(
                    &log_range_check));

    positional_.add("binary-desc", -1);
}

void fbf::CommandLineParser::parse() {
    try {
        po::store(po::command_line_parser(argc_, argv_)
                          .options(generic_)
                          .positional(positional_)
                          .run(), vm_);
        po::notify(vm_);
    } catch (const boost::program_options::error &e) {
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
}

size_t fbf::CommandLineParser::count(const char *key) {
    if (!cmd_parsed_) {
        throw std::runtime_error("Command line arguments not parsed");
    }

    return vm_.count(key);
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
    logging::core::get()->set_filter(
            logging::trivial::severity >= log_level_
    );
    if(!log_path_.empty()) {
        logging::add_file_log(log_path_.c_str());
    }
}
