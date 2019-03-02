import io
import os
import random
import stat
import struct
import subprocess
import threading
import select

from .FBLogging import logger
from .IOVec import IOVec


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
    ZMSG_READY = 8
    HEADER_FORMAT = "iQ"

    names = {
        ZMSG_FAIL: "ZMSG_FAIL",
        ZMSG_OK: "ZMSG_OK",
        ZMSG_ACK: "ZMSG_ACK",
        ZMSG_SET_TGT: "ZMSG_SET_TGT",
        ZMSG_EXIT: "ZMSG_EXIT",
        ZMSG_FUZZ: "ZMSG_FUZZ",
        ZMSG_EXECUTE: "ZMSG_EXECUTE",
        ZMSG_SET_CTX: "ZMSG_SET_CTX",
        ZMSG_RESET: "ZMSG_RESET",
        ZMSG_READY: "ZMSG_READY"
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
            self.data = io.BytesIO(data)

    def write_to_pipe(self, pipe):
        pipe.write(struct.pack(PinMessage.HEADER_FORMAT, self.msgtype, self.msglen))
        if self.msglen > 0:
            pipe.write(self.data.read())


class PinRun:
    def __init__(self, pin_loc, pintool_loc, binary_loc, loader_loc=None, pipe_in=None, pipe_out=None,
                 log_loc=None, cwd=os.getcwd(), cmd_log_loc=None):
        self.binary_loc = os.path.abspath(binary_loc)
        if not os.path.exists(self.binary_loc):
            raise FileNotFoundError("{} does not exist".format(self.binary_loc))

        self.pin_loc = os.path.abspath(pin_loc)
        if not os.path.exists(self.pin_loc):
            raise FileNotFoundError("{} does not exist".format(self.pin_loc))

        self.pintool_loc = os.path.abspath(pintool_loc)
        if not os.path.exists(self.pintool_loc):
            raise FileNotFoundError("{} does not exist".format(self.pintool_loc))

        self.cwd = os.path.abspath(cwd)
        if not os.path.exists(self.cwd):
            os.makedirs(self.cwd, exist_ok=True)

        if loader_loc is not None:
            self.loader_loc = os.path.abspath(loader_loc)
            if not os.path.exists(self.loader_loc):
                raise FileNotFoundError("{} does not exist".format(self.loader_loc))

        if log_loc is not None:
            self.log_loc = os.path.abspath(log_loc)
            if os.path.exists(self.log_loc):
                os.unlink(self.log_loc)
        else:
            self.log_loc = None

        if cmd_log_loc is not None:
            self.cmd_log_loc = os.path.abspath(cmd_log_loc)
            if os.path.exists(self.cmd_log_loc):
                os.unlink(self.cmd_log_loc)
        else:
            self.cmd_log_loc = None

        if pipe_in is None:
            self.pipe_in_loc = os.path.join(cwd, "{}.{}.in".format(os.path.basename(self.binary_loc), random.randint()))
        else:
            self.pipe_in_loc = os.path.abspath(pipe_in)

        self.create_pipe_in = False
        if not os.path.exists(self.pipe_in_loc):
            self.create_pipe_in = True
        elif not stat.S_ISFIFO(os.stat(self.pipe_in_loc).st_mode):
            raise AssertionError("{} is not a pipe".format(self.pipe_in_loc))

        if pipe_out is None:
            self.pipe_out_loc = os.path.join(cwd, "{}.{}.out".format(os.path.basename(self.binary_loc),
                                                                     random.randint()))
        else:
            self.pipe_out_loc = os.path.abspath(pipe_out)

        self.create_pipe_out = False
        if not os.path.exists(self.pipe_out_loc):
            self.create_pipe_out = True
        elif not stat.S_ISFIFO(os.stat(self.pipe_out_loc).st_mode):
            raise AssertionError("{} is not a pipe".format(self.pipe_out_loc))

        self.accepted_contexts = list()
        self.pin_thread = None
        self.pin_proc = None
        self.pipe_in = None
        self.pipe_out = None
        self.thr_r = None
        self.thr_w = None
        self.log = None

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
        cmd = [self.pin_loc]
        if self.log_loc is not None:
            cmd.append("-logfile")
            cmd.append(os.path.join(self.cwd, os.path.basename(self.log_loc) + ".pin"))

        cmd.append("-t")
        cmd.append(self.pintool_loc)
        cmd.append("-in-pipe")
        cmd.append(self.pipe_in_loc)
        cmd.append("-out-pipe")
        cmd.append(self.pipe_out_loc)

        if self.log_loc is not None:
            cmd.append("-log")
            cmd.append(self.log_loc)
        if self.cmd_log_loc is not None:
            cmd.append("-cmdlog")
            cmd.append(self.cmd_log_loc)

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
        self.log = open(self.log_loc, "a+")

        self.pin_proc = subprocess.Popen(cmd, cwd=self.cwd, close_fds=True, stdout=self.log, stderr=self.log)
        # self.pin_proc = subprocess.Popen(cmd, cwd=self.cwd, close_fds=True)
        pid = self.pin_proc.pid
        logger.debug("{} spawned process {}".format(os.path.basename(self.pipe_in_loc), pid))
        self.pin_proc.wait()
        logger.debug("Pin process {} ended".format(pid))
        if self.log is not None:
            self.log.close()
        self.log = None
        if self.thr_w is not None:
            os.write(self.thr_w, struct.pack("i", PinMessage.ZMSG_EXIT))

    def is_running(self):
        # logger.debug("pipe_in: {}".format(self.pipe_in is not None))
        # logger.debug("pipe_out: {}".format(self.pipe_out is not None))
        # logger.debug("pin_thread: {}".format(self.pin_thread is not None))
        # if self.pin_thread is not None:
        #     logger.debug("pin_thread.is_alive: {}".format(self.pin_thread.is_alive()))

        return self.pipe_in is not None and self.pipe_out is not None and self.pin_thread is \
               not None and self.pin_thread.is_alive()

    def _send_cmd(self, cmd, data, timeout=None):
        if not self.is_running():
            raise AssertionError("Process not running")

        fuzz_cmd = PinMessage(cmd, data)
        logger.debug("Writing {} msg with {} bytes of data to {}".format(PinMessage.names[fuzz_cmd.msgtype],
                                                                         fuzz_cmd.msglen,
                                                                         os.path.basename(self.pipe_in_loc)))
        fuzz_cmd.write_to_pipe(self.pipe_in)

        response = self.read_response(timeout)
        return response

    def start(self, timeout=None):
        if self.is_running():
            raise AssertionError("Already started")

        if self.create_pipe_in:
            os.mkfifo(self.pipe_in_loc)

        if self.create_pipe_out:
            os.mkfifo(self.pipe_out_loc)

        self.thr_r, self.thr_w = os.pipe()
        self.pin_thread = threading.Thread(target=self._run)
        self.pin_thread.start()

        logger.debug("Opening pipe_in {}".format(self.pipe_in_loc))
        self.pipe_in = open(self.pipe_in_loc, "wb", buffering=0)
        logger.debug("Opening pipe_out {}".format(self.pipe_out_loc))
        self.pipe_out = os.open(self.pipe_out_loc, os.O_RDONLY)

        self.wait_for_ready(timeout)

    def stop(self):
        logger.debug("Stopping PinRun for {}".format(os.path.basename(self.pipe_in_loc)))
        try:
            if self.is_running():
                self._send_cmd(PinMessage.ZMSG_EXIT, None, 0.1)
        except BrokenPipeError:
            logger.debug("Error sending {} for {}".format(PinMessage.names[PinMessage.ZMSG_EXIT],
                                                          os.path.basename(self.pipe_in_loc)))
            pass
        finally:
            self.pin_thread.join(timeout=0.1)
            if self.pin_thread.is_alive():
                if self.pin_proc is not None:
                    self.pin_proc.kill()
                    if self.pin_proc.stdout is not None:
                        logger.debug("Closing pin_proc.stdout for {}".format(os.path.basename(self.pipe_in_loc)))
                        self.pin_proc.stdout.close()
                    if self.pin_proc.stderr is not None:
                        logger.debug("Closing pin_proc.stderr for {}".format(os.path.basename(self.pipe_in_loc)))
                        self.pin_proc.stderr.close()
                    if self.pin_proc.stdin is not None:
                        logger.debug("Closing pin_proc.stdin for {}".format(os.path.basename(self.pipe_in_loc)))
                        self.pin_proc.stdin.close()
                    self.pin_proc = None

            if self.thr_r is not None:
                os.close(self.thr_r)
                self.thr_r = None
            if self.thr_w is not None:
                os.close(self.thr_w)
                self.thr_w = None

            if self.log is not None:
                if not self.log.closed:
                    self.log.close()
                self.log = None

            if self.pipe_in is not None:
                logger.debug("Closing pipe_in for {}".format(os.path.basename(self.pipe_in_loc)))
                self.pipe_in.close()
                self.pipe_in = None

            if self.create_pipe_in:
                os.unlink(self.pipe_in_loc)

            if self.pipe_out is not None:
                logger.debug("Closing pipe_out for {}".format(os.path.basename(self.pipe_in_loc)))
                os.close(self.pipe_out)
                self.pipe_out = None

            if self.create_pipe_out:
                os.unlink(self.pipe_out_loc)

            logger.info("PinRun stopped for {}".format(os.path.basename(self.pipe_in_loc)))

    def wait_for_ready(self, timeout=None):
        byte_data = []
        while len(byte_data) == 0:
            ready_pipes = select.select([self.thr_r, self.pipe_out], [], [], timeout)
            if len(ready_pipes[0]) == 0:
                raise AssertionError("Pin process timed out waiting for ready")
            if self.thr_r in ready_pipes[0]:
                raise AssertionError("Pin process exited while waiting for ready")
            if self.pipe_out in ready_pipes[0]:
                byte_data = os.read(self.pipe_out, struct.calcsize(PinMessage.HEADER_FORMAT))

        header_data = struct.unpack_from(PinMessage.HEADER_FORMAT, byte_data)
        msgtype = header_data[0]
        msglen = header_data[1]

        if msgtype != PinMessage.ZMSG_READY:
            raise AssertionError("Server did not issue a {} msg: {} (len = {})".format(
                PinMessage.names[PinMessage.ZMSG_READY],
                PinMessage.names[msgtype], msglen))

    def send_fuzz_cmd(self, timeout=None):
        return self._send_cmd(PinMessage.ZMSG_FUZZ, None, timeout)

    def send_execute_cmd(self, timeout=None):
        return self._send_cmd(PinMessage.ZMSG_EXECUTE, None, timeout)

    def send_reset_cmd(self, timeout=None):
        return self._send_cmd(PinMessage.ZMSG_RESET, None, timeout)

    def read_response(self, timeout=None):
        result = None
        while result is None:
            if not self.is_running():
                raise AssertionError("Process for {} not running".format(os.path.basename(self.pipe_out_loc)))
            ready_pipes = select.select([self.thr_r, self.pipe_out], [], [], timeout)
            if len(ready_pipes[0]) == 0:
                break

            if self.thr_r in ready_pipes[0]:
                raise AssertionError(
                    "Pin process for {} exited prematurely".format(os.path.basename(self.pipe_out_loc)))
            if self.pipe_out in ready_pipes[0]:
                pipe_data = os.read(self.pipe_out, struct.calcsize(PinMessage.HEADER_FORMAT))
                if len(pipe_data) == 0:
                    continue
                header_data = struct.unpack_from(PinMessage.HEADER_FORMAT, pipe_data)
                msgtype = header_data[0]
                msglen = header_data[1]

                if msglen > 0:
                    data = os.read(self.pipe_out, msglen)
                else:
                    data = None
                result = PinMessage(msgtype, data)

        if result is not None:
            logger.debug(
                "Received {} msg with {} bytes back on {}".format(PinMessage.names[result.msgtype],
                                                                  result.msglen, os.path.basename(self.pipe_out_loc)))
        else:
            logger.debug("Received No message back on {}".format(os.path.basename(self.pipe_out_loc)))
        return result

    def send_set_target_cmd(self, target, timeout=None):
        logger.debug("Setting target to {} for {}".format(hex(target), os.path.basename(self.pipe_out_loc)))
        return self._send_cmd(PinMessage.ZMSG_SET_TGT, struct.pack("Q", target), timeout)

    def send_set_ctx_cmd(self, io_vec, timeout=None):
        if io_vec is None:
            raise AssertionError("io_vec cannot be None")
        elif not isinstance(io_vec, IOVec):
            raise AssertionError("io_vec must be an instance of IOVec")

        data = io.BytesIO()
        io_vec.write_bin(data)
        if len(data.getbuffer()) == 0:
            raise AssertionError("IOVec is empty")

        return self._send_cmd(PinMessage.ZMSG_SET_CTX, data.getbuffer(), timeout)
