//
// Created by derrick on 11/19/18.
//

#ifndef FOSBIN_FOSBINFUZZER_H
#define FOSBIN_FOSBINFUZZER_H

#include <iTestCase.h>
#include <tuple>
#include <TupleHelpers.h>
#include <random>
#include <sys/wait.h>
#include <iomanip>

namespace fbf {
    /*****************************************************************************************************
     * ********************************* Fuzz argument functions *****************************************
     ******************************************************************************************************/
    template<typename Arg, typename std::enable_if<std::is_pointer_v<Arg>, int>::type = 0>
    static Arg generate_arg(Arg arg, size_t size, int seed) {
        /* Purposefully return original pointer argument, because the pointer is
         * supposed to be backed by a valid memory region */
        Arg buf = std::malloc(size);
        std::memcpy(buf, arg, size);
        return buf;
    }

    template<typename Arg, typename std::enable_if<std::is_integral_v<Arg>, int>::type = 0>
    static Arg generate_arg(Arg arg, size_t size, int seed) {
        std::default_random_engine generator;
        generator.seed(seed);
        std::uniform_int_distribution<Arg> distribution;
        Arg retVal = distribution(generator);
        LOG_DEBUG << "Returning integer " << retVal;
        return retVal;
    }

    template<typename Arg, typename std::enable_if<std::is_floating_point_v<Arg>, int>::type = 0>
    static Arg generate_arg(Arg arg, size_t size, int seed) {
        std::default_random_engine generator;
        generator.seed(seed);
        std::uniform_real_distribution<Arg> distribution;
        Arg retVal = distribution(generator);
        LOG_DEBUG << "Returning float " << retVal;
        return retVal;
    }

    template<typename... Args, size_t... I>
    static void fuzz_argument(size_t pointer_size, int seed, std::tuple<Args...> &tup, std::index_sequence<I...>) {
        ((std::get<I>(tup) = generate_arg(std::get<I>(tup), pointer_size, seed)), ...);
    }

    template<typename... Args>
    static void fuzz_arguments(size_t pointer_size, int seed, std::tuple<Args...> &tup) {
        fuzz_argument(pointer_size, seed, tup, std::make_index_sequence<sizeof...(Args)>());
    }

    /*****************************************************************************************************
     * ***************************** Clean up argument functions *****************************************
     ******************************************************************************************************/
    template<typename Arg, typename std::enable_if<std::is_pointer_v<Arg>, int>::type = 0>
    static void cleanup_arg(Arg arg) {
        return free(arg);
    }

    template<typename Arg, typename std::enable_if<!std::is_pointer_v<Arg>, int>::type = 0>
    static void cleanup_arg(Arg arg) {
        return;
    }

    template<typename... Args, size_t... I>
    static void cleanup_fold(std::tuple<Args...> &tup, std::index_sequence<I...>) {
        ((cleanup_arg(std::get<I>(tup))), ...);
    }

    template<typename... Args>
    static void cleanup_args(std::tuple<Args...> &tup) {
        cleanup_fold(tup, std::make_index_sequence<sizeof...(Args)>());
    }

    /*****************************************************************************************************
     * ******************************* Output argument functions *****************************************
     ******************************************************************************************************/
    template<typename Arg, typename std::enable_if<std::is_void_v<Arg>, int>::type = 0>
    static std::string output_arg_json() {
        std::stringstream s;
        s << "{";
        s << "\"type\": " << 0 << ", \"value\": (nil)";
        s << "}";
        return s.str();
    }

    template<typename Arg, typename std::enable_if<!std::is_void_v<Arg>, int>::type = 0>
    static std::string output_arg_json(size_t pointer_size, Arg prearg, Arg postarg) {
        std::stringstream s;
        s << "{";
        /* TODO: Replace hard coded values with values from TypeID enum */
        if constexpr (std::is_pointer_v<Arg>) {
            uint8_t *tmp_pre = reinterpret_cast<uint8_t *>(prearg);
            uint8_t *tmp_post = reinterpret_cast<uint8_t *>(postarg);
            s << "\"type\": " << 15
              << ", \"size\": " << pointer_size
              << ", \"precall\": \"";
            for (size_t i = 0; i < pointer_size; i++) {
                int val = ((int)tmp_pre[i] & 0x000000FF);
                if(tmp_pre[i] < 0x10) {
                    s << "\\\\x0";
                } else {
                    s << "\\\\x";
                }
                s << std::hex << val << std::dec;
            }

            s << "\", postcall: \"";
            for (size_t i = 0; i < pointer_size; i++) {
                int val = ((int)tmp_post[i] & 0x000000FF);
                if(tmp_post[i] < 0x10) {
                    s << "\\\\x0";
                } else {
                    s << "\\\\x";
                }
                s << std::hex << val << std::dec;
            }

            s << "\"";
        } else {
            int type = 0;
            int size = sizeof(Arg);
            if constexpr(std::is_integral_v<Arg>) {
                type = 11;
            } else {
                if (typeid(Arg) == typeid(float)) {
                    type = 2;
                } else if (typeid(Arg) == typeid(double)) {
                    type = 3;
                } else if (typeid(Arg) == typeid(long double)) {
                    type = 4;
                }
            }
            s << "\"type\": " << type << ", \"size\": " << size << ", \"value\": " << std::setprecision(std::numeric_limits<Arg>::digits10) << postarg;
        }
        s << "}";
        return s.str();
    }

    template<typename... Args, size_t... I>
    static void output_json_args(std::ostream &out, size_t pointer_size, std::tuple<Args...> &precall,
                                 std::tuple<Args...> &postcall, std::index_sequence<I...>) {

        ((out << output_arg_json(pointer_size, std::get<I>(precall), std::get<I>(postcall))
            << (I < sizeof...(Args) - 1 ? ", " : "")), ...);
    }

    template<typename... Args>
    static std::string output_args(size_t pointer_size, std::tuple<Args...> &precall,
                                   std::tuple<Args...> &postcall) {
        std::stringstream s;
        output_json_args(s, pointer_size, precall, postcall, std::make_index_sequence<sizeof...(Args)>());
        return s.str();
    }

    /* ************************************************************************************************
     * ************************************** Class Declaration ***************************************
     * ************************************************************************************************/
    template<typename R, typename... Args>
    class FosbinFuzzer : public ITestCase {
    public:
        FosbinFuzzer(BinaryDescriptor &binDesc, std::tuple<Args...> args, uint32_t fuzz_count = 60);

        virtual const std::string get_test_name();

        virtual int run_test();

        virtual arity_t get_arity();

    protected:
        std::tuple<Args...> original_;
        std::tuple<Args...> curr_args_;
        BinaryDescriptor &bin_desc_;

        void mutate_args();
        uint32_t fuzz_count_;
    };

    /* ************************************************************************************************
     * ************************************** Class Definition ****************************************
     * ************************************************************************************************/
    template<typename R, typename... Args>
    FosbinFuzzer<R, Args...>::FosbinFuzzer(BinaryDescriptor &binDesc, std::tuple<Args...> args, uint32_t fuzz_count) :
            ITestCase(),
            fuzz_count_(fuzz_count),
            bin_desc_(binDesc) {
        original_ = args;
        curr_args_ = original_;
        set_location(0);
    }

    template<typename R, typename... Args>
    const std::string FosbinFuzzer<R, Args...>::get_test_name() {
        return bin_desc_.getSym(get_location()).name;
    }

    template<typename R, typename... Args>
    int FosbinFuzzer<R, Args...>::run_test() {
        if (location_ == 0) {
            throw std::runtime_error("Unset fuzzing location");
        }

        std::function<R(Args...)> func = reinterpret_cast<R(*)(Args...)>(location_);
        const LofSymbol &symbol = bin_desc_.getSym(location_);
        pid_t pid = test_fork();
        if (pid == 0) {
            for (int i = 0; i < fuzz_count_; i++) {
                mutate_args();

                LOG_DEBUG << "Fuzzing 0x" << std::hex << location_ << std::dec
                          << " with arguments " << print_args(curr_args_);

                std::stringstream s;
                s << "{ \"function\": { \"name\": \"" << symbol.name << "\", "
                  << "\"return\": ";

                if constexpr (std::is_void_v<R>) {
                    std::apply(func, curr_args_);
                    s << output_arg_json<void>();
                    LOG_DEBUG << "Void function returned";
                } else {
                    R retVal = std::apply(func, curr_args_);
                    LOG_DEBUG << "Function returned " << retVal;
                    s << output_arg_json(ITestCase::POINTER_SIZE, retVal, retVal);
                }

                s << ", \"args\": ["
                  << output_args(ITestCase::POINTER_SIZE, original_, curr_args_)
                  << "]} }" << std::endl;

                std::cout << s.str();
            }

            LOG_DEBUG << "Done fuzzing 0x" << std::hex << location_;
            exit(ITestCase::PASS);
        } else if (pid > 0) {
            int status;
            LOG_DEBUG << "Process " << getpid() << " is waiting on " << pid << " to finish fuzzing";
            waitpid(pid, &status, 0);
            if (!WIFEXITED(status)) {
                LOG_DEBUG << "Function faulted";
            } else if (WEXITSTATUS(status) != ITestCase::PASS) {
                LOG_DEBUG << "Function exited with exit code " << WEXITSTATUS(status);
            }
            return (WIFEXITED(status) && WEXITSTATUS(status) == ITestCase::PASS);
        }

        /* This shouldn't happen, but I don't want compile warnings */
        throw std::runtime_error("Invalid fork value");
    }

    template<typename R, typename... Args>
    void FosbinFuzzer<R, Args...>::mutate_args() {
        /* TODO: Remove hardcoded pointer size value */
        fuzz_arguments(ITestCase::POINTER_SIZE, this->rand(), curr_args_);
    }

    template<typename R, typename... Args>
    arity_t FosbinFuzzer<R, Args...>::get_arity() {
        return sizeof...(Args);
    }
}


#endif //FOSBIN_FOSBINFUZZER_H
