//
// Created by derrick on 10/10/18.
//

#ifndef FOSBIN_COMMANDLINEPARSER_H
#define FOSBIN_COMMANDLINEPARSER_H

#include <boost/program_options.hpp>
#include <experimental/filesystem>
#include "fosbin-config.h"

namespace fbf {
    namespace po = boost::program_options;
    namespace fs = std::experimental::filesystem;
    namespace logging = boost::log;

    class CommandLineParser {
    public:
        CommandLineParser(int argc, char** argv, const char* name);
        void parse();
        size_t count(const char* key);
        void print_help();
        const po::variable_value& operator[](const std::string& name) const;
        void add_option(const char* name,
                   const char* description);
        void add_option(const char* name,
                   const po::value_semantic* s);
        void add_option(const char* name,
                   const po::value_semantic* s,
                   const char* description);
    protected:
        int argc_, log_level_i_;
        char** argv_;
        po::variables_map vm_;
        po::options_description generic_;
        po::positional_options_description positional_;
        const char* name_;
        fs::path log_path_;
        logging::trivial::severity_level log_level_;
        bool cmd_parsed_;

        void init_logging();
    };
}

#endif //FOSBIN_COMMANDLINEPARSER_H
