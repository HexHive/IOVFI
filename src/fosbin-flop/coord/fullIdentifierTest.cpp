//
// Created by derrick on 7/8/18.
//

#include "fosbin-flop/fullIdentifierTest.h"
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

fbf::FullIdentifierTest::FullIdentifierTest(fs::path descriptor, uint32_t thread_count) :
        FullTest(descriptor, thread_count) {
    create_testcases();
}

fbf::FullIdentifierTest::~FullIdentifierTest() {}

void fbf::FullIdentifierTest::create_testcases() {
    const std::set<std::string> identifiers = fbf::IdentifierFactory::Instance()->getRegistered();

    for (std::set<uintptr_t>::iterator it = binDesc_.getOffsets().begin();
         it != binDesc_.getOffsets().end(); ++it) {
        uintptr_t addr = compute_location(*it);
        for (std::set<std::string>::iterator it2 = identifiers.begin();
             it2 != identifiers.end(); ++it2) {
            std::shared_ptr<fbf::FunctionIdentifier> id =
                    fbf::IdentifierFactory::Instance()->CreateIdentifier(*it2, addr);
            testRuns_.push_back(std::make_shared<fbf::TestRun>(id, *it));
        }
    }
}
