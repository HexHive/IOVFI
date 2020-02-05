//
// Created by derrick on 2/4/20.
//

#ifndef FOSBIN_ZERGMESSAGE_H
#define FOSBIN_ZERGMESSAGE_H

#include "IOVec.h"
#include "ExecutionInfo.h"

typedef enum zerg_message_type {
    ZMSG_FAIL = -1,
    ZMSG_OK,
    ZMSG_ACK,
    ZMSG_SET_TGT,
    ZMSG_EXIT,
    ZMSG_FUZZ,
    ZMSG_EXECUTE,
    ZMSG_SET_CTX,
    ZMSG_RESET,
    ZMSG_READY,
    ZMSG_SET_SO_TGT,
//    ZMSG_GET_EXE_INFO,
    ZMSG_SET_RUST_TGT
} zerg_message_t;

class ZergMessage {
protected:
    zerg_message_t _message_type;
    size_t _length;
    void *_data;
    bool _self_allocated_data;
public:
    ZergMessage(zerg_message_t type, size_t length, void *data);

    ZergMessage(zerg_message_t type = ZMSG_FAIL);

    ZergMessage(const ZergMessage &msg);

    ~ZergMessage();

    size_t read_from_fd(int fd);

    size_t write_to_fd(int fd) const;

    size_t size() const;

    zerg_message_t type() const;

    void *data() const;

    const char *str() const;

    size_t add_IOVec(IOVec &iovec);

//    size_t add_contexts(const FBZergContext &pre, const FBZergContext &post);

//    size_t add_exe_info(const ExecutionInfo &info);
};

#endif //FOSBIN_ZERGMESSAGE_H
