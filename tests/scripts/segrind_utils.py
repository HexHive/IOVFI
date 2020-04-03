import struct

# target_func = "is_pid_and_argc_even\x00"
# target_func = "foo\x00"
# target_func = "main\x00"
# target_func = "print_global1\x00"

empty_fmt = "=iQ"

set_tgt_fmt = empty_fmt + "Q"

write_pipe = open('pipe.in', 'wb')
read_pipe = open('pipe.out', 'rb')


def read_msg():
    (msg_type, length) = struct.unpack_from(empty_fmt, read_pipe.read(struct.calcsize(empty_fmt)))
    print("Got ({}, {}) from command pipe".format(msg_type, length))
    if length > 0:
        read_pipe.read(length)


read_msg()


def send_set_target(addr):
    write_pipe.write(struct.pack(set_tgt_fmt, 2, struct.calcsize('Q'), addr))
    write_pipe.flush()
    read_msg()
    read_msg()


def send_fuzz_and_execute():
    write_pipe.write(struct.pack(empty_fmt, 4, 0))
    write_pipe.flush()
    read_msg()
    read_msg()
    write_pipe.write(struct.pack(empty_fmt, 5, 0))
    write_pipe.flush()
    read_msg()
    read_msg()


def send_exit():
    write_pipe.write(struct.pack(empty_fmt, 3, 0))
    write_pipe.flush()
