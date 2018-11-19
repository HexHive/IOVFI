//
// Created by derrick on 9/17/18.
//

#ifndef FOSBIN_BINARYDESCRIPTOR_H
#define FOSBIN_BINARYDESCRIPTOR_H

#include <map>
#include <binSection.h>
#include <fosbin-config.h>

namespace fbf {
    struct LofSymbol {
        std::string name;
        size_t size;
        arity_t arity;
        bool isHidden;

        LofSymbol(std::string n, size_t s, arity_t a, bool h = false) : name(n), size(s), arity(a), isHidden(h) {}

        LofSymbol(const LofSymbol &other) {
            name = other.name;
            size = other.size;
            arity = other.arity;
            isHidden = other.isHidden;
        }

        void operator=(const LofSymbol &other) {
            name = other.name;
            size = other.size;
            arity = other.arity;
            isHidden = other.isHidden;
        }
    };

    class BinaryDescriptor {
    protected:
        std::set<uintptr_t> offsets_;
        fs::path bin_path_, desc_path_;
        BinSection text_;
        BinSection data_;
        BinSection bss_;
        std::map<uintptr_t, std::shared_ptr<LofSymbol>> syms_;
        uintptr_t errno_location_;
        uint64_t identifier_;
        std::map<int32_t, std::set<uint16_t>> syscall_mapping_;

        uintptr_t parse_offset(std::string &offset);

        void check_for_good_file(fs::path path);

        bool getline(std::fstream &f, std::string &s);

    public:
        BinaryDescriptor(fs::path desc_path);

        BinaryDescriptor(fs::path desc_path, fs::path syscall_mapping);

        ~BinaryDescriptor();

        BinSection &getText();

        BinSection &getData();

        BinSection &getBss();

        fs::path &getPath();

        std::set<uintptr_t> getOffsets();

        const LofSymbol &getSym(uintptr_t location);

        const LofSymbol &getFunc(uintptr_t location);

        uintptr_t getSymLocation(const LofSymbol &sym);

        uintptr_t getSymLocation(const std::string sym);

        int getErrno();

        bool isSharedLibrary();

        uint64_t getIdentifier();

        void setIdentifier(uint64_t id);

        std::set<uint16_t> getSyscallRegisters(uint32_t syscall);

        void parse_syscall_mapping(fs::path syscall_mapping);

        void parse_aritys(fs::path aritys);
    };
}

#endif //FOSBIN_BINARYDESCRIPTOR_H
