//
// Created by derrick on 9/17/18.
//

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
#include <random>

namespace fs = std::experimental::filesystem;

fbf::BinaryDescriptor::BinaryDescriptor(fs::path path) :
        desc_path_(path), errno_location_(0) {
    unsigned seed = std::chrono::system_clock::now().time_since_epoch().count();
    std::default_random_engine re(seed);
    std::uniform_int_distribution<uint64_t> longrand(std::numeric_limits<uint64_t>::min(),
                                                     std::numeric_limits<uint64_t>::max());
    identifier_ = longrand(re);

    if (fs::is_empty(desc_path_)) {
        throw std::runtime_error("Descriptor is empty");
    }

    if (fs::is_directory(desc_path_)) {
        throw std::runtime_error("Descriptor is a directory");
    }

    size_t line_num = 0;
    std::fstream f(path);
    std::string line;
    std::set<std::pair<std::string, size_t>> syms;
    std::set<std::string> tests;

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
            LOG_ERR << msg;
            throw std::runtime_error(msg.c_str());
        }

        std::string key = line.substr(0, index);
        std::string val = line.substr(index + 1);

        if (key == "binary") {
            bin_path_ = val.c_str();
            if (!fs::exists(bin_path_)) {
                std::string msg = "Could not find binary at ";
                msg += val;
                LOG_ERR << msg;
                throw std::runtime_error(msg.c_str());
            }
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
            continue;
        } else if (key == "bss_offset") {
            bss_.offset_ = parse_offset(val);
            continue;
        } else if (key == "data_location") {
            uintptr_t location = parse_offset(val);
            data_.location_ = location;
            continue;
        } else if (key == "data_offset") {
            data_.offset_ = parse_offset(val);
            continue;
        } else if (key == "sym") {
            size_t sep = val.find(',');
            if(sep == std::string::npos) {
                std::stringstream msg;
                msg << "Malformed symbol entry on line " << line_num;
                LOG_ERR << msg.str();
                throw std::runtime_error(msg.str());
            }

            std::string name = val.substr(0, sep);

            std::stringstream str_size;
            str_size << val.substr(sep + 1);

            size_t size = 0;
            str_size >> size;
            if(size == 0) {
                std::stringstream msg;
                msg << "Invalid function size on line " << line_num;
                LOG_ERR << msg.str();
                throw std::runtime_error(msg.str());
            }

            syms.insert(std::make_pair(name, size));
            continue;
        } else if (key == "test") {
            tests.insert(val);
            continue;
        } else {
            std::string msg = "Unknown key: ";
            msg += key;
            LOG_ERR << msg;
            throw std::runtime_error(msg.c_str());
        }
    }

    if (bin_path_.empty()) {
        LOG_ERR << "Binary path is required.";
        throw std::runtime_error("Binary path is required.");
    }

    if (isSharedLibrary()) {
        if (syms.empty()) {
            LOG_ERR << "At least one symbol must be provided.";
            throw std::runtime_error("At least one symbol must be provided.");
        }

        void *offset = dlopen(bin_path_.c_str(), RTLD_LAZY);
        if (!offset) {
            std::string msg(dlerror());
            LOG_ERR << msg;
            throw std::runtime_error(msg);
        }

        dlerror();
        text_.location_ = (uintptr_t) offset;
        for (std::pair<std::string, size_t> p : syms) {
            offset = dlsym((void *) text_.location_, p.first.c_str());
            if (!offset) {
                LOG_ERR << "Could not find symbol " << p.first << std::endl;
                continue;
            }
            std::cout << std::hex << offset << std::dec << "=" << p.first << std::endl;

            syms_[(uintptr_t) offset] = p;
            if(tests.find(p.first) != tests.end()) {
                offsets_.insert((uintptr_t)offset);
            } else if(tests.empty()) {
                offsets_.insert((uintptr_t)offset);
            }
        }

        offset = dlsym((void*)text_.location_, "__errno_location");
        if(offset) {
            LOG_DEBUG << "Found __errno_location at " << std::hex << offset;
            errno_location_ = (uintptr_t)offset;
        }

    } else {
        if (offsets_.empty()) {
            LOG_ERR << "At least one offset required.";
            throw std::runtime_error("At least one offset required.");
        }

        struct stat st;

        int fd = open(bin_path_.c_str(), O_RDONLY);
        if (fd < 0) {
            LOG_ERR << "Could not open binary " << bin_path_;
            throw std::runtime_error("Could not open binary");
        }
        if (fstat(fd, &st) < 0) {
            close(fd);
            LOG_ERR << "Failed to get binary stats";
            throw std::runtime_error("Failed to get binary stats");
        }
        text_.size_ = st.st_size;

        void *offset = mmap(NULL, text_.size_,
                            PROT_EXEC | PROT_READ,
                            MAP_PRIVATE, fd, 0);

        if (offset == MAP_FAILED) {
            close(fd);
            LOG_FATAL << "Failed to memory map binary";
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
                LOG_ERR << msg;
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
                LOG_ERR << msg;
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

const std::pair<std::string, size_t> fbf::BinaryDescriptor::getSym(uintptr_t location) {
    if(syms_.find(location) != syms_.end()) {
        return syms_[location];
    }

    std::vector<uintptr_t> addrs;
    for(auto v : syms_) {
        addrs.push_back(v.first);
    }

    std::pair<std::string, size_t> lower, upper;
    std::sort(addrs.begin(), addrs.end());
    size_t i;
    for(i = 1; i < addrs.size(); i++) {
        if(addrs[i] > location) {
            upper = syms_[addrs[i]];
            lower = syms_[addrs[i - 1]];
            break;
        }
    }

    if(location < addrs[i - 1] + lower.second) {
        return syms_[addrs[i - 1]];
    } else {
        /* This is a function with hidden visibility, but presumably it is there */
        return std::make_pair("", addrs[i] - location);
    }
}

const std::pair<std::string, size_t> fbf::BinaryDescriptor::getFunc(uintptr_t location) {
    if(syms_.find(location) == syms_.end()) {
        return std::make_pair("", 0);
    }

    return syms_[location];
}

uint64_t fbf::BinaryDescriptor::getIdentifier() {
    return identifier_;
}

void fbf::BinaryDescriptor::setIdentifier(uint64_t id) {
    identifier_ = id;
}

uintptr_t fbf::BinaryDescriptor::getSymLocation(std::pair<std::string, size_t> sym) {
    for(auto v : syms_) {
        if(v.second.first == sym.first) {
            return v.first;
        }
    }

    return (uintptr_t)-1;
}