//
// Created by derrick on 10/10/18.
//

#ifndef FOSBIN_COMMANDLINEPARSER_H
#define FOSBIN_COMMANDLINEPARSER_H

#include <boost/program_options.hpp>
#include <experimental/filesystem>

namespace fbf {
    namespace po = boost::program_options;
    namespace fs = std::experimental::filesystem;

    class CommandLineParser {
    public:
        CommandLineParser(int argc, char** argv);
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
        int argc_;
        char** argv_;
        po::variables_map vm_;
        po::options_description generic_;
        po::positional_options_description positional_;

    private:
        bool cmd_parsed;
    };
}

#endif //FOSBIN_COMMANDLINEPARSER_H
