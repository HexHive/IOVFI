//
// Created by derrick on 7/8/18.
//

#include "fullTest.h"

fbf::FullTest::FullTest(fs::path descriptor) :
        descriptor_(descriptor) {
    if (fs::is_empty(descriptor_)) {
        throw std::runtime_error("Descriptor is empty");
    }

    if (fs::is_directory(descriptor_)) {
        throw std::runtime_error("Descriptor is a directory");
    }

    parse_descriptor();
}

fbf::FullTest::~FullTest() = default;

void fbf::FullTest::run() {
    for (std::vector<std::unique_ptr<fbf::TestRun>>::iterator it = testRuns_.begin();
         it != testRuns_.end(); ++it) {
        (*it)->run_test();
    }
}

void fbf::FullTest::output(std::ostream &out) {
    for (std::vector<std::unique_ptr<fbf::TestRun>>::iterator it = testRuns_.begin();
         it != testRuns_.end(); ++it) {
        (*it)->output_results(out);
    }
}

void fbf::FullTest::parse_descriptor() {
    /* TODO: Implement this */
}
