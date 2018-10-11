//
// Created by derrick on 10/10/18.
//
#include <iostream>
#include <commandLineParser.h>

fbf::CommandLineParser::CommandLineParser(int argc, char **argv, const char *name) :
        argc_(argc),
        argv_(argv),
        generic_("Generic Options"),
        positional_(),
        vm_(),
        cmd_parsed(false),
        name_(name),
        log_path_() {
    generic_.add_options()
            ("version,v", "Prints version string")
            ("help,h", "Prints this message")
            ("binary-desc,i", po::value<fs::path>()->required(), "/path/to/binary/descriptor")
            ("log", po::value<fs::path>(&log_path_), "/path/to/log/file");

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

    cmd_parsed = true;

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
    if (!cmd_parsed) {
        throw std::runtime_error("Command line arguments not parsed");
    }

    return vm_.count(key);
}

void fbf::CommandLineParser::print_help() {
    std::cout << generic_ << std::endl;
}

const boost::program_options::variable_value &fbf::CommandLineParser::operator[](const std::string &name) const {
    if (!cmd_parsed) {
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
            logging::trivial::severity >= logging::trivial::info
            );
}
