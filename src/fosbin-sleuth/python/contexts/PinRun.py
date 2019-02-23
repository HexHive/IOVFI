import os
import subprocess
import stat
import threading
import struct
import io
from .IOVec import IOVec
from .FBLogging import logger


class PinMessage:
    ZMSG_FAIL = -1
    ZMSG_OK = 0
    ZMSG_SET_TGT = 1
    ZMSG_EXIT = 2
    ZMSG_FUZZ = 3
    ZMSG_EXECUTE = 4
    ZMSG_SET_CTX = 5
    ZMSG_RESET = 6
    HEADER_FORMAT = "=iQ"

    names = {
        ZMSG_FAIL: "ZMSG_FAIL",
        ZMSG_OK: "ZMSG_OK",
        ZMSG_SET_TGT: "ZMSG_SET_TGT",
        ZMSG_EXIT: "ZMSG_EXIT",
        ZMSG_FUZZ: "ZMSG_FUZZ",
        ZMSG_EXECUTE: "ZMSG_EXECUTE",
        ZMSG_SET_CTX: "ZMSG_SET_CTX",
        ZMSG_RESET: "ZMSG_RESET"
    }

    def __init__(self, type, data):
        if type not in PinMessage.names:
            raise ValueError("Invalid message type: {}".format(type))
        self.type = type
        if data is None:
            self.len = 0
            self.data = None
        else:
            self.len = len(data)
            self.data = data

    def write_to_pipe(self, pipe):
        pipe.write(struct.pack(PinMessage.HEADER_FORMAT, self.type, self.len))
        if self.len > 0:
            pipe.write(self.data)

    @staticmethod
    def read_from_pipe(pipe):
        header_data = struct.unpack_from(PinMessage.HEADER_FORMAT,
                                         os.read(pipe, struct.calcsize(PinMessage.HEADER_FORMAT)))
        type = header_data[0]
        len = header_data[1]

        if len > 0:
            data = os.read(pipe, len)
        else:
            data = None

        return PinMessage(type, data)


class PinRun:
    def __init__(self, pin_loc, pintool_loc, binary_loc, target, loader_loc=None, pipe_in=None, pipe_out=None,
                 log_loc=None, cwd=os.getcwd()):
        self.binary_loc = os.path.abspath(binary_loc)

        try:
            self.target = hex(int(target, 16))
        except Exception:
            self.target = target

        self.pin_loc = os.path.abspath(pin_loc)
        self.pintool_loc = os.path.abspath(pintool_loc)
        self.cwd = os.path.abspath(cwd)
        if loader_loc is not None:
            self.loader_loc = os.path.abspath(loader_loc)

        if log_loc is not None:
            self.log_loc = os.path.abspath(log_loc)
        else:
            self.log_loc = None

        if pipe_in is None:
            self.pipe_in_loc = os.path.join(cwd, "{}.{}.in".format(os.path.basename(self.binary_loc), target))
        else:
            self.pipe_in_loc = os.path.abspath(pipe_in)

        if not os.path.exists(self.pipe_in_loc):
            os.mkfifo(self.pipe_in_loc)
        elif not stat.S_ISFIFO(os.stat(self.pipe_in_loc).st_mode):
            raise AssertionError("{} is not a pipe".format(self.pipe_in_loc))

        if pipe_out is None:
            self.pipe_out_loc = os.path.join(cwd, "{}.{}.out".format(os.path.basename(self.binary_loc), target))
        else:
            self.pipe_out_loc = os.path.abspath(pipe_out)

        if not os.path.exists(self.pipe_out_loc):
            os.mkfifo(self.pipe_out_loc)
        elif not stat.S_ISFIFO(os.stat(self.pipe_out_loc).st_mode):
            raise AssertionError("{} is not a pipe".format(self.pipe_out_loc))

        self.fuzz_count = 0
        self.accepted_contexts = list()
        self.pin_thread = threading.Thread(target=self._run)
        self.pin_proc = None
        self.pipe_in = None
        self.pipe_out = None

    def _check_state(self):
        if self.pin_loc is None:
            raise ValueError("pin_loc is None")
        if self.pintool_loc is None:
            raise ValueError("pintool_loc is None")
        if self.binary_loc is None:
            raise ValueError("binary_loc is None")
        if self.target is None:
            raise ValueError("function is None")
        if os.path.splitext(self.binary_loc)[1] == ".so" and self.loader_loc is None:
            raise ValueError("loader_loc is None")
        if not stat.S_ISFIFO(os.stat(self.pipe_in).st_mode):
            raise AssertionError("{} is not a pipe".format(self.pipe_in))
        if not stat.S_ISFIFO(os.stat(self.pipe_out).st_mode):
            raise AssertionError("{} is not a pipe".format(self.pipe_out))

    def generate_cmd(self):
        cmd = [self.pin_loc, "-t", self.pintool_loc, "-in-pipe", self.pipe_in, "-out-pipe", self.pipe_out]

        if self.log_loc is not None:
            cmd.append("-log")
            cmd.append(os.path.abspath(self.log_loc))

        cmd.append("--")

        if os.path.splitext(self.binary_loc)[1] == ".so":
            cmd.append(self.loader_loc)
            cmd.append(self.binary_loc)
        else:
            cmd.append(self.binary_loc)

        return cmd

    def _run(self):
        self._check_state()
        cmd = self.generate_cmd()

        logger.info("Running {}".format(" ".join(cmd)))

        self.pin_proc = subprocess.Popen(cmd, cwd=self.cwd)

    def is_running(self):
        return self.pipe_in is not None and self.pipe_out is not None and self.pin_thread.is_alive()

    def _send_cmd(self, cmd, data):
        if not self.is_running():
            raise AssertionError("Process not started")

        fuzz_cmd = PinMessage(cmd, data)
        fuzz_cmd.write_to_pipe(self.pipe_in)

        response = PinMessage.read_from_pipe(self.pipe_out)
        return response

    def start(self):
        if self.is_running():
            raise AssertionError("Already started")

        self.pipe_in = open(self.pipe_in_loc, "wb", buffering=0)
        self.pipe_out = os.open(self.pipe_out_loc, os.O_RDONLY)

        self.pin_thread.start()

    def stop(self):
        if not self.is_running():
            raise AssertionError("Process not started")

        exit_msg = PinMessage(PinMessage.ZMSG_EXIT, None)
        exit_msg.write_to_pipe(self.pipe_in)
        self.pipe_in.close()
        os.close(self.pipe_out)

        self.pin_thread.join(timeout=0.1)
        if self.pin_thread.is_alive():
            self.pin_proc.kill()

    def send_fuzz_cmd(self):
        return self._send_cmd(PinMessage.ZMSG_FUZZ, None)

    def send_execute_cmd(self):
        return self._send_cmd(PinMessage.ZMSG_EXECUTE, None)

    def send_reset_cmd(self):
        return self._send_cmd(PinMessage.ZMSG_RESET, None)

    def read_response(self):
        return PinMessage.read_from_pipe(self.pipe_out)

    def send_set_target_cmd(self, target):
        return self._send_cmd(PinMessage.ZMSG_SET_TGT, struct.pack("=Q", target))

    def send_set_ctx_cmd(self, io_vec):
        if io_vec is None:
            raise AssertionError("io_vec cannot be None")
        elif not isinstance(io_vec, IOVec):
            raise AssertionError("io_vec must be an instance of IOVec")

        data = io.BytesIO()
        io_vec.write_bin(data)
        if len(data) == 0:
            raise AssertionError("IOVec is empty")

        return self._send_cmd(PinMessage.ZMSG_SET_CTX, data)

    def returncode(self):
        if not self.pin_thread.is_alive() and self.pin_proc is not None:
            return self.pin_proc.returncode

        return None
