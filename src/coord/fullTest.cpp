//
// Created by derrick on 7/8/18.
//

#include "fullTest.h"
#include <fstream>
#include <set>
#include <algorithm>
#include <experimental/filesystem>
#include <identifiers/identifierFactory.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace fs = std::experimental::filesystem;

fbf::FullTest::FullTest(fs::path descriptor) :
        descriptor_(descriptor), mmap_loc_(0) {
    if (fs::is_empty(descriptor_)) {
        throw std::runtime_error("Descriptor is empty");
    }

    if (fs::is_directory(descriptor_)) {
        throw std::runtime_error("Descriptor is a directory");
    }

    parse_descriptor();
}

fbf::FullTest::~FullTest() {
    if(mmap_loc_ > 0) {
        munmap((void*)mmap_loc_, mmap_size_);
    }
}

void fbf::FullTest::run() {
    size_t test_num = 0;
    for (std::vector<std::shared_ptr<fbf::TestRun>>::iterator it = testRuns_.begin();
         it != testRuns_.end(); ++it) {
        std::cout << "Running measurement " << ++test_num << " of "
            << testRuns_.size() << std::endl;
        (*it)->run_test();
    }
}

void fbf::FullTest::output(std::ostream &out) {
    for (std::vector<std::shared_ptr<fbf::TestRun>>::iterator it = testRuns_.begin();
         it != testRuns_.end(); ++it) {
        (*it)->output_results(out);
    }
}

void fbf::FullTest::parse_descriptor() {
    std::fstream f(descriptor_);
    std::string line;

    std::set<uintptr_t> offsets;

    size_t line_num = 0;
    const std::set<std::string> identifiers = fbf::IdentifierFactory::Instance()->getRegistered();
    while(std::getline(f, line)) {
        line_num++;
        std::remove_if(line.begin(), line.end(), isspace);
        if(line.empty() || line[0] == '#') {
            continue;
        }

        size_t index = line.find('=');
        if(index == std::string::npos) {
            std::string msg = "Invalid line at line ";
            msg += line_num;
            msg += ": ";
            msg += line;
            throw std::runtime_error(msg.c_str());
        }

        std::string key = line.substr(0, index);
        std::string val = line.substr(index + 1);

        if(key == "binary") {
            bin_path_ = val.c_str();
            if(!fs::exists(bin_path_)) {
                std::string msg = "Could not find binary at ";
                msg += val;
                throw std::runtime_error(msg.c_str());
            }
            continue;
        } else if(key == "addr") {
            std::istringstream iss(val);
            uintptr_t addr = 0;
            iss >> std::hex >> addr;
            if(offsets.find(addr) != offsets.end()) {
                continue;
            }
            offsets.insert(addr);
            continue;
        } else {
            std::string msg = "Unknown key: ";
            msg += key;
            throw std::runtime_error(msg.c_str());
        }
    }

    if(bin_path_.empty() || offsets.empty()) {
        throw std::runtime_error("Binary path and at least one offset required.");
    }

    struct stat st;

    int fd = open(bin_path_.c_str(), O_RDONLY);
    if(fd < 0) {
        throw std::runtime_error("Could not open binary");
    }
    if(fstat(fd, &st) < 0) {
        close(fd);
        throw std::runtime_error("Failed to get binary stats");
    }

    void* offset = mmap(NULL, st.st_size, PROT_EXEC | PROT_READ, MAP_PRIVATE, fd, 0);
    if(!offset) {
        close(fd);
        throw std::runtime_error("Failed to memory map binary");
    }
    close(fd);
    mmap_loc_ = (uintptr_t)offset;
    mmap_size_= st.st_size;

    for(std::set<uintptr_t>::iterator it = offsets.begin();
        it != offsets.end(); ++it) {
        uintptr_t addr = mmap_loc_ + *it;
        for(std::set<std::string>::iterator it2 = identifiers.begin();
            it2 != identifiers.end(); ++it2) {
            std::shared_ptr<fbf::FunctionIdentifier> id =
                    fbf::IdentifierFactory::Instance()->CreateIdentifier(*it2, addr);
            testRuns_.push_back(std::make_shared<fbf::TestRun>(id));
        }
    }
}
