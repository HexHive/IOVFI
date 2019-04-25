//
// Created by derrick on 11/17/18.
//

#ifndef FOSBIN_TUPLEHELPERS_H
#define FOSBIN_TUPLEHELPERS_H

#include <iostream>
#include <sstream>
#include <string>
#include "fosbin-config.h"
#include <iomanip>

namespace fbf {
    template<typename Arg, typename std::enable_if<std::is_pointer_v<Arg>, int>::type = 0>
    static bool check_arg2(const Arg prearg, const Arg postarg, size_t size) {
        bool is_same = true;
        if (prearg && postarg) {
            is_same = std::strncmp(prearg, postarg, size) == 0;
        }
        LOG_DEBUG << "pointer args are " << (is_same ? "" : "NOT ") << "the same";
        return is_same;
    }

    template<typename Arg, typename std::enable_if<!std::is_pointer_v<Arg>, int>::type = 0>
    static bool check_arg2(const Arg prearg, const Arg postarg, size_t size) {
        LOG_DEBUG << "Non-pointer arg";
        return true;
    }

    template<typename Tup, size_t... I>
    static bool check_tuple_arg(const Tup &pretup, const Tup &posttup, const std::vector<size_t> &sizes,
                                std::index_sequence<I...>) {
        return (
                ((check_arg2(std::get<I>(pretup), std::get<I>(posttup), sizes[I]))) && ...);
    }

    template<typename Tup, size_t... I>
    static void print_arg(std::ostream &out, const Tup &tup, std::index_sequence<I...>) {
        out << "(";
        (..., (out << (I == 0 ? "" : ", ") << std::hex << std::get<I>(tup)));
        out << ")";
    }

/* *********************************************************************************
 * ************************ Public Functions ***************************************
 * ********************************************************************************* */
    template<typename... T>
    bool check_tuple_args(const std::tuple<T...> &pretup, const std::tuple<T...> &posttup, const std::vector<size_t>
    &sizes) {
        return check_tuple_arg(pretup, posttup, sizes, std::make_index_sequence<sizeof...(T)>());
    }


    template<typename... T>
    std::string print_args(const std::tuple<T...> &tup) {
        std::stringstream out;
        print_arg(out, tup, std::make_index_sequence<sizeof...(T)>());
        return out.str();
    }
}
#endif //FOSBIN_TUPLEHELPERS_H
