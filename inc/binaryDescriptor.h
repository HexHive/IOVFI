//
// Created by derrick on 9/17/18.
//

#ifndef FOSBIN_BINARYDESCRIPTOR_H
#define FOSBIN_BINARYDESCRIPTOR_H
#include <set>
#include <map>
#include "binSection.h"
#include <experimental/filesystem>
#include "fosbin-config.h"

namespace fs = std::experimental::filesystem;

namespace fbf {
    class BinaryDescriptor {
    protected:
        std::set<uintptr_t> offsets_;
        fs::path bin_path_, desc_path_;
        BinSection text_;
        BinSection data_;
        BinSection bss_;
        std::map<uintptr_t, std::pair<std::string, size_t>> syms_;
        uintptr_t errno_location_;
        uint64_t identifier_;
        std::map<int32_t, std::set<uint16_t>> syscall_mapping_;

        uintptr_t parse_offset(std::string &offset);

    public:
        BinaryDescriptor(fs::path desc_path);
        BinaryDescriptor(fs::path desc_path, fs::path syscall_mapping);
        ~BinaryDescriptor();
        BinSection& getText();
        BinSection& getData();
        BinSection& getBss();
        fs::path& getPath();
        std::set<uintptr_t> getOffsets();
        const std::pair<std::string, size_t> getSym(uintptr_t location);
        const std::pair<std::string, size_t> getFunc(uintptr_t location);
        uintptr_t getSymLocation(std::pair<std::string, size_t> sym);
        uintptr_t getSymLocation(std::string sym);
        int getErrno();
        bool isSharedLibrary();
        uint64_t getIdentifier();
        void setIdentifier(uint64_t id);
        std::set<uint16_t> getSyscallRegisters(uint32_t syscall);
        void parse_syscall_mapping(fs::path syscall_mapping);
    };
}

#endif //FOSBIN_BINARYDESCRIPTOR_H
