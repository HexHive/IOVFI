//
// Created by derrick on 9/17/18.
//

#include "binaryDescriptor.h"
#include <fstream>
#include <string>
#include <algorithm>
#include <experimental/filesystem>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cstring>
#include <binaryDescriptor.h>
#include <dlfcn.h>
#include <iostream>
#include <functional>


namespace fs = std::experimental::filesystem;

fbf::BinaryDescriptor::BinaryDescriptor(fs::path path) :
        desc_path_(path), errno_location_(0) {
    if (fs::is_empty(desc_path_)) {
        throw std::runtime_error("Descriptor is empty");
    }

    if (fs::is_directory(desc_path_)) {
        throw std::runtime_error("Descriptor is a directory");
    }

    size_t line_num = 0;
    std::fstream f(path);
    std::string line;
    std::set<std::string> syms;

    while (std::getline(f, line)) {
        line_num++;
        std::remove_if(line.begin(), line.end(), isspace);
        if (line.empty() || line[0] == '#') {
            continue;
        }

        size_t index = line.find('=');
        if (index == std::string::npos) {
            std::string msg = "Invalid line at line ";
            msg += line_num;
            msg += ": ";
            msg += line;
            throw std::runtime_error(msg.c_str());
        }

        std::string key = line.substr(0, index);
        std::string val = line.substr(index + 1);

        if (key == "binary") {
            bin_path_ = val.c_str();
            if (!fs::exists(bin_path_)) {
                std::string msg = "Could not find binary at ";
                msg += val;
                throw std::runtime_error(msg.c_str());
            }
            continue;
        } else if (key == "addr") {
            uintptr_t addr = parse_offset(val);
            if (offsets_.find(addr) != offsets_.end()) {
                continue;
            }
            offsets_.insert(addr);
            continue;
        } else if (key == "data_size" ||
                   key == "bss_size") {
            size_t size = (size_t) parse_offset(val);
            if (key == "data_size") {
                data_.size_ = size;
            } else {
                bss_.size_ = size;
            }
            continue;
        } else if (key == "bss_location") {
            uintptr_t location = parse_offset(val);
            bss_.location_ = location;
        } else if (key == "bss_offset") {
            bss_.offset_ = parse_offset(val);
        } else if (key == "data_location") {
            uintptr_t location = parse_offset(val);
            data_.location_ = location;
        } else if (key == "data_offset") {
            data_.offset_ = parse_offset(val);
        } else if (key == "sym") {
            syms.insert(val);
        } else {
            std::string msg = "Unknown key: ";
            msg += key;
            throw std::runtime_error(msg.c_str());
        }
    }

    if (bin_path_.empty()) {
        throw std::runtime_error("Binary path is required.");
    }

    if (isSharedLibrary()) {
        if (syms.empty()) {
            throw std::runtime_error("At least one symbol must be provided.");
        }

        void *offset = dlopen(bin_path_.c_str(), RTLD_LAZY);
        if (!offset) {
            throw std::runtime_error(dlerror());
        }

        dlerror();
        text_.location_ = (uintptr_t) offset;
        for (std::string s : syms) {
            offset = dlsym((void *) text_.location_, s.c_str());
            if (!offset) {
                std::cerr << "Could not find symbol " << s << std::endl;
                continue;
            }
            std::cout << std::hex << offset << std::dec << "=" << s << std::endl;

            offsets_.insert((uintptr_t) offset);
            syms_[(uintptr_t) offset] = s;
        }

        offset = dlsym((void*)text_.location_, "__errno_location");
        if(offset) {
            errno_location_ = (uintptr_t)offset;
        }

    } else {
        if (offsets_.empty()) {
            throw std::runtime_error("At least one offset required.");
        }

        struct stat st;

        int fd = open(bin_path_.c_str(), O_RDONLY);
        if (fd < 0) {
            throw std::runtime_error("Could not open binary");
        }
        if (fstat(fd, &st) < 0) {
            close(fd);
            throw std::runtime_error("Failed to get binary stats");
        }
        text_.size_ = st.st_size;

        void *offset = mmap(NULL, text_.size_,
                            PROT_EXEC | PROT_READ,
                            MAP_PRIVATE, fd, 0);

        if (offset == MAP_FAILED) {
            close(fd);
            throw std::runtime_error("Failed to memory map binary");
        }
        close(fd);
        text_.location_ = (uintptr_t) offset;

        if (bss_.size_ > 0) {
            offset = mmap((void *) (text_.location_ + bss_.location_),
                          bss_.size_, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
            if (offset == MAP_FAILED) {
                char *err = strerror(errno);
                std::string msg = "Failed to memory map BSS: ";
                msg += err;
                throw std::runtime_error(msg);
            }
            bss_.location_ = (uintptr_t) offset;
            std::memcpy((void *) bss_.location_, (void *) (text_.location_ + bss_.offset_), bss_.size_);
        }

        if (data_.size_ > 0) {
            offset = mmap((void *) (text_.location_ + data_.location_),
                          data_.size_, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
            if (offset == MAP_FAILED) {
                char *err = strerror(errno);
                std::string msg = "Failed to memory map data: ";
                msg += err;
                throw std::runtime_error(msg);
            }
            data_.location_ = (uintptr_t) offset;
        }
    }
}

int fbf::BinaryDescriptor::getErrno() {
    if(isSharedLibrary() && errno_location_) {
        std::function<int*()> errno_loc = reinterpret_cast<int*(*)()>(errno_location_);
        return *errno_loc();
    }

    return errno;
}

uintptr_t fbf::BinaryDescriptor::parse_offset(std::string &offset) {
    std::istringstream iss(offset);
    uintptr_t addr = 0;
    iss >> std::hex >> addr;
    return addr;
}

fbf::BinaryDescriptor::~BinaryDescriptor() {
    if (text_.location_ > 0) {
        if (isSharedLibrary()) {
            dlclose((void *) text_.location_);
        } else {
            munmap((void *) text_.location_, text_.size_);
        }
    }

    if (data_.location_ > 0) {
        munmap((void *) data_.location_, data_.size_);
    }

    if (bss_.location_ > 0) {
        munmap((void *) bss_.location_, bss_.size_);
    }
}

fbf::BinSection &fbf::BinaryDescriptor::getText() {
    return text_;
}

fbf::BinSection &fbf::BinaryDescriptor::getData() {
    return data_;
}

fbf::BinSection &fbf::BinaryDescriptor::getBss() {
    return bss_;
}

fs::path &fbf::BinaryDescriptor::getPath() {
    return bin_path_;
}

std::set<uintptr_t> fbf::BinaryDescriptor::getOffsets() {
    return offsets_;
}

bool fbf::BinaryDescriptor::isSharedLibrary() {
    return bin_path_.extension() == ".so" ||
           bin_path_.string().find(".so.") != std::string::npos;
}

const std::string fbf::BinaryDescriptor::getSym(uintptr_t location) {
    if (syms_.find(location) == syms_.end()) {
        return "";
    }

    return syms_[location];
}