//
// Created by derrick on 7/8/18.
//

#include "fosbin-flop/fullTest.h"
#include <fstream>
#include <set>
#include <algorithm>
#include <experimental/filesystem>
#include <identifiers/identifierFactory.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cstring>
#include <termios.h>

namespace fs = std::experimental::filesystem;

fbf::FullTest::FullTest(fs::path descriptor) :
        binDesc_(descriptor) {
        parse_descriptor();
}

fbf::FullTest::~FullTest() { }

void fbf::FullTest::run() {
    size_t test_num = 0;
    struct termios in, out, err;
    tcgetattr(0, &in);
    tcgetattr(1, &out);
    tcgetattr(2, &err);

    for (std::vector<std::shared_ptr<fbf::TestRun>>::iterator it = testRuns_.begin();
         it != testRuns_.end(); ++it) {
        std::stringstream offset;
        offset << std::hex << (*it)->get_offset();
        tcsetattr(0, 0, &in);
        tcsetattr(1, 0, &out);
        tcsetattr(2, 0, &err);
        std::cout << "Running measurement " << ++test_num
                  << " (offset 0x" << offset.str() << ") of "
                  << testRuns_.size() << std::endl;
        (*it)->run_test();
    }
}

void fbf::FullTest::output(std::ostream &out) {
    size_t i = 0;
    size_t total = testRuns_.size();
    for (; i < total; i++) {
        out << "Outputting " << i << " of " << total - 1 << std::endl;
        testRuns_[i]->output_results(out);
    }
}

void fbf::FullTest::parse_descriptor() {
    const std::set<std::string> identifiers = fbf::IdentifierFactory::Instance()->getRegistered();

    for (std::set<uintptr_t>::iterator it = binDesc_.getOffsets().begin();
         it != binDesc_.getOffsets().end(); ++it) {
        uintptr_t addr = binDesc_.getText().location_ + *it;
        for (std::set<std::string>::iterator it2 = identifiers.begin();
             it2 != identifiers.end(); ++it2) {
            std::shared_ptr<fbf::FunctionIdentifier> id =
                    fbf::IdentifierFactory::Instance()->CreateIdentifier(*it2, addr);
            testRuns_.push_back(std::make_shared<fbf::TestRun>(id, *it));
        }
    }
}
