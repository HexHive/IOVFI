import os
import subprocess
import stat
import threading
import struct
import io
import random
from .IOVec import IOVec
from .FBLogging import logger


class PinMessage:
    ZMSG_FAIL = -1
    ZMSG_OK = 0
    ZMSG_ACK = 1
    ZMSG_SET_TGT = 2
    ZMSG_EXIT = 3
    ZMSG_FUZZ = 4
    ZMSG_EXECUTE = 5
    ZMSG_SET_CTX = 6
    ZMSG_RESET = 7
    HEADER_FORMAT = "=iQ"

    names = {
        ZMSG_FAIL: "ZMSG_FAIL",
        ZMSG_OK: "ZMSG_OK",
        ZMSG_ACK: "ZMSG_ACK",
        ZMSG_SET_TGT: "ZMSG_SET_TGT",
        ZMSG_EXIT: "ZMSG_EXIT",
        ZMSG_FUZZ: "ZMSG_FUZZ",
        ZMSG_EXECUTE: "ZMSG_EXECUTE",
        ZMSG_SET_CTX: "ZMSG_SET_CTX",
        ZMSG_RESET: "ZMSG_RESET"
    }

    def __init__(self, msgtype, data):
        if msgtype not in PinMessage.names:
            raise ValueError("Invalid message type: {}".format(msgtype))

        self.msgtype = msgtype
        if data is None:
            self.msglen = 0
            self.data = None
        else:
            self.msglen = len(data)
            self.data = data
        logger.debug("Created {} msg with {} bytes of data".format(PinMessage.names[self.msgtype], self.msglen))

    def write_to_pipe(self, pipe):
        logger.debug("Writing {} msg with {} bytes of data".format(PinMessage.names[self.msgtype], self.msglen))
        pipe.write(struct.pack(PinMessage.HEADER_FORMAT, self.msgtype, self.msglen))
        if self.msglen > 0:
            pipe.write(self.data)

    @staticmethod
    def read_from_pipe(pipe):
        logger.debug("Reading from {}".format(pipe))
        pipe_data = os.read(pipe, struct.calcsize(PinMessage.HEADER_FORMAT))
        logger.debug("pipe returned {} bytes: {}".format(len(pipe_data), pipe_data))
        header_data = struct.unpack_from(PinMessage.HEADER_FORMAT, pipe_data)
        msgtype = header_data[0]
        msglen = header_data[1]

        if msglen > 0:
            data = os.read(pipe, msglen)
        else:
            data = None

        return PinMessage(msgtype, data)


class PinRun:
    def __init__(self, pin_loc, pintool_loc, binary_loc, loader_loc=None, pipe_in=None, pipe_out=None,
                 log_loc=None, cwd=os.getcwd()):
        self.binary_loc = os.path.abspath(binary_loc)

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
            self.pipe_in_loc = os.path.join(cwd, "{}.{}.in".format(os.path.basename(self.binary_loc), random.randint()))
        else:
            self.pipe_in_loc = os.path.abspath(pipe_in)

        if not os.path.exists(self.pipe_in_loc):
            os.mkfifo(self.pipe_in_loc)
        elif not stat.S_ISFIFO(os.stat(self.pipe_in_loc).st_mode):
            raise AssertionError("{} is not a pipe".format(self.pipe_in_loc))

        if pipe_out is None:
            self.pipe_out_loc = os.path.join(cwd, "{}.{}.out".format(os.path.basename(self.binary_loc),
                                                                     random.randint()))
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
        if os.path.splitext(self.binary_loc)[1] == ".so" and self.loader_loc is None:
            raise ValueError("loader_loc is None")
        if not stat.S_ISFIFO(os.stat(self.pipe_in_loc).st_mode):
            raise AssertionError("{} is not a pipe".format(self.pipe_in_loc))
        if not stat.S_ISFIFO(os.stat(self.pipe_out_loc).st_mode):
            raise AssertionError("{} is not a pipe".format(self.pipe_out_loc))

    def generate_cmd(self):
        cmd = [self.pin_loc, "-t", self.pintool_loc, "-in-pipe", self.pipe_in_loc, "-out-pipe", self.pipe_out_loc]

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

        self.pin_proc = subprocess.Popen(cmd, cwd=self.cwd, close_fds=True)
        self.pin_proc.wait()

    def is_running(self):
        return self.pipe_in is not None and self.pipe_out is not None and self.pin_thread.is_alive()

    def _send_cmd(self, cmd, data):
        if not self.is_running():
            raise AssertionError("Process not running")

        logger.debug("Writing {} msg".format(PinMessage.names[cmd]))
        fuzz_cmd = PinMessage(cmd, data)
        fuzz_cmd.write_to_pipe(self.pipe_in)

        response = PinMessage.read_from_pipe(self.pipe_out)
        return response

    def start(self):
        if self.is_running():
            raise AssertionError("Already started")

        self.pin_thread.start()

        logger.debug("Opening pipe_in {}".format(self.pipe_in_loc))
        self.pipe_in = open(self.pipe_in_loc, "wb", buffering=0)
        logger.debug("Opening pipe_out {}".format(self.pipe_out_loc))
        self.pipe_out = os.open(self.pipe_out_loc, os.O_RDONLY)

    def stop(self):
        logger.debug("Stopping PinRun")
        try:
            if self.is_running():
                self._send_cmd(PinMessage.ZMSG_EXIT, None)
        except BrokenPipeError:
            logger.debug("Error sending {}".format(PinMessage.names[PinMessage.ZMSG_EXIT]))
            pass
        finally:
            self.pin_thread.join(timeout=0.1)
            if self.pin_thread.is_alive():
                if self.pin_proc is not None:
                    self.pin_proc.kill()
                    if self.pin_proc.stdout is not None:
                        logger.debug("Closing pin_proc.stdout")
                        self.pin_proc.stdout.close()
                    if self.pin_proc.stderr is not None:
                        logger.debug("Closing pin_proc.stderr")
                        self.pin_proc.stderr.close()
                    if self.pin_proc.stdin is not None:
                        logger.debug("Closing pin_proc.stdin")
                        self.pin_proc.stdin.close()
                    self.pin_proc = None

            if self.pipe_in is not None:
                logger.debug("Closing pipe_in")
                self.pipe_in.close()
                self.pipe_in = None

            if self.pipe_out is not None:
                logger.debug("Closing pipe_out")
                os.close(self.pipe_out)
                self.pipe_out = None
            logger.debug("PinRun stopped")

    def send_fuzz_cmd(self):
        return self._send_cmd(PinMessage.ZMSG_FUZZ, None)

    def send_execute_cmd(self):
        return self._send_cmd(PinMessage.ZMSG_EXECUTE, None)

    def send_reset_cmd(self):
        return self._send_cmd(PinMessage.ZMSG_RESET, None)

    def read_response(self):
        if not self.is_running():
            raise AssertionError("Process not running")
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
        if len(data.getbuffer()) == 0:
            raise AssertionError("IOVec is empty")

        return self._send_cmd(PinMessage.ZMSG_SET_CTX, data)

    def returncode(self):
        if not self.pin_thread.is_alive() and self.pin_proc is not None:
            return self.pin_proc.returncode

        return None
