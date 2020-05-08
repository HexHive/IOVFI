import io
import os
import random
import select
import stat
import struct
import subprocess
import sys
from enum import IntEnum, unique, auto

import contexts.binaryutils as bu

from .FBLogging import logger
from .IOVec import IOVec


@unique
class SEMsgType(IntEnum):
    SEMSG_FAIL = -1
    SEMSG_OK = auto()
    SEMSG_ACK = auto()
    SEMSG_SET_TGT = auto()
    SEMSG_EXIT = auto()
    SEMSG_FUZZ = auto()
    SEMSG_EXECUTE = auto()
    SEMSG_SET_CTX = auto()
    SEMSG_READY = auto()
    SEMSG_RESET = auto()
    SEMSG_SET_SO_TGT = auto()
    SEMSG_NEW_ALLOC = auto()
    SEMSG_FAILED_CTX = auto()
    SEMSG_TOO_MANY_INS = auto()
    SEMSG_TOO_MANY_ATTEMPTS = auto()
    SEMSG_COVERAGE = auto()
    SEMSG_TIMEOUT = auto()


class SEMessage:
    HEADER_FORMAT = "=iQ"

    def __init__(self, msgtype, data):
        self.msgtype = msgtype
        if data is None:
            self.msglen = 0
            self.data = None
        else:
            self.msglen = len(data)
            self.data = data

    def __str__(self):
        return self.msgtype.name

    def write_to_pipe(self, pipe):
        pipe.write(struct.pack(SEMessage.HEADER_FORMAT, self.msgtype.value, self.msglen))
        if self.msglen > 0:
            pipe.write(self.data)
        pipe.flush()

    def get_coverage(self):
        # TODO: Implement me
        coverage = list()
        return coverage


class SEGrindRun:
    def __init__(self, valgrind_loc, binary_loc, timeout, pipe_in=None, pipe_out=None, valgrind_log_loc=None,
                 run_log_loc=None, cwd=os.getcwd(), toolname="segrind"):
        self.binary_loc = os.path.abspath(binary_loc)
        if not os.path.exists(self.binary_loc):
            raise FileNotFoundError("{} does not exist".format(self.binary_loc))

        if toolname is None or len(toolname) == 0:
            raise AssertionError("toolname cannot be empty")
        self.toolname = toolname

        self.valgrind_loc = os.path.abspath(valgrind_loc)
        if not os.path.exists(self.valgrind_loc):
            raise FileNotFoundError("{} does not exist".format(self.valgrind_loc))

        self.cwd = os.path.abspath(cwd)
        if not os.path.exists(self.cwd):
            os.makedirs(self.cwd, exist_ok=True)

        if valgrind_log_loc is not None:
            self.valgrind_log_loc = os.path.abspath(valgrind_log_loc)
            if not os.path.exists(os.path.dirname(self.valgrind_log_loc)):
                os.makedirs(os.path.dirname(self.valgrind_log_loc), exist_ok=True)
        else:
            self.valgrind_log_loc = None

        if run_log_loc is not None:
            self.run_log_loc = os.path.abspath(run_log_loc)
            if not os.path.exists(os.path.dirname(self.run_log_loc)):
                os.makedirs(os.path.dirname(self.run_log_loc), exist_ok=True)
        else:
            self.run_log_loc = None

        if pipe_in is None:
            self.pipe_in_loc = os.path.join(cwd,
                                            "{}.{}.in".format(os.path.basename(self.binary_loc),
                                                              random.randint(0, sys.maxsize)))
        else:
            self.pipe_in_loc = os.path.abspath(pipe_in)

        self.create_pipe_in = False
        if not os.path.exists(self.pipe_in_loc):
            self.create_pipe_in = True
        elif not stat.S_ISFIFO(os.stat(self.pipe_in_loc).st_mode):
            raise AssertionError("{} is not a pipe".format(self.pipe_in_loc))

        if pipe_out is None:
            self.pipe_out_loc = os.path.join(cwd, "{}.{}.out".format(os.path.basename(self.binary_loc),
                                                                     random.randint(0, sys.maxsize)))
        else:
            self.pipe_out_loc = os.path.abspath(pipe_out)

        self.create_pipe_out = False
        if not os.path.exists(self.pipe_out_loc):
            self.create_pipe_out = True
        elif not stat.S_ISFIFO(os.stat(self.pipe_out_loc).st_mode):
            raise AssertionError("{} is not a pipe".format(self.pipe_out_loc))

        self.accepted_contexts = list()
        # self.valgrind_thread = None
        self.valgrind_proc = None
        self.valgrind_pid = None
        self.pipe_in = None
        self.pipe_out = None
        self.log = None
        self.timeout = timeout

    def _check_state(self):
        if self.valgrind_loc is None:
            raise ValueError("pin_loc is None")
        if self.binary_loc is None:
            raise ValueError("binary_loc is None")
        if not stat.S_ISFIFO(os.stat(self.pipe_in_loc).st_mode):
            raise AssertionError("{} is not a pipe".format(self.pipe_in_loc))
        if not stat.S_ISFIFO(os.stat(self.pipe_out_loc).st_mode):
            raise AssertionError("{} is not a pipe".format(self.pipe_out_loc))

    def generate_cmd(self):
        cmd = [self.valgrind_loc, "--tool={}".format(self.toolname)]

        if self.valgrind_log_loc is not None:
            cmd.append("--log-file={}".format(self.valgrind_log_loc))

        cmd.append("--in-pipe={}".format(self.pipe_in_loc))
        cmd.append("--out-pipe={}".format(self.pipe_out_loc))
        if self.timeout:
            cmd.append("--max-duration={}".format(self.timeout))
        cmd.append(self.binary_loc)

        return cmd

    def _run(self):
        self._check_state()
        cmd = self.generate_cmd()

        logger.debug("Running {}".format(" ".join(cmd)))
        if self.run_log_loc is not None:
            self.log = open(self.run_log_loc, "a+")

        env_copy = os.environ.copy()
        env_copy['LD_BIND_NOW'] = "1"

        self.valgrind_proc = subprocess.Popen(cmd, cwd=self.cwd, close_fds=True, stdout=self.log, stderr=self.log,
                                              env=env_copy)
        self.valgrind_pid = self.valgrind_proc.pid
        logger.debug("{} spawned process {}".format(os.path.basename(self.pipe_in_loc), self.valgrind_pid))
        # ret_value = self.valgrind_proc.wait()
        # logger.debug("Valgrind process {} ended with return code {}".format(self.valgrind_pid, ret_value))
        # if self.log is not None:
        #     self.log.close()
        # self.log = None
        # self.valgrind_pid = None
        # if self.thr_w is not None:
        #     os.write(self.thr_w, struct.pack("i", SEMsgType.SEMSG_EXIT.value))

    def is_running(self):
        # logger.debug("pipe_in: {}".format(self.pipe_in is not None))
        # logger.debug("pipe_out: {}".format(self.pipe_out is not None))
        # logger.debug("pin_thread: {}".format(self.pin_thread is not None))
        # if self.pin_thread is not None:
        #     logger.debug("pin_thread.is_alive: {}".format(self.pin_thread.is_alive()))

        return self.pipe_in is not None and self.pipe_out is not None and self.valgrind_proc is \
               not None and self.valgrind_proc.returncode is None

    def _send_cmd(self, cmd, data, timeout=None):
        if not self.is_running():
            raise AssertionError("Process not running")
        if timeout is None:
            timeout = self.timeout

        cmd_msg = SEMessage(cmd, data)
        logger.debug("Writing {} msg with {} bytes of data to {} {}".format(cmd_msg.msgtype.name,
                                                                            cmd_msg.msglen, self.valgrind_pid,
                                                                            os.path.basename(self.pipe_in_loc)))
        cmd_msg.write_to_pipe(self.pipe_in)

        response = self.read_response(timeout)
        return response

    def start(self):
        if self.is_running():
            raise AssertionError("Already started")

        if self.create_pipe_in:
            if not os.path.exists(os.path.dirname(self.pipe_in_loc)):
                os.makedirs(os.path.dirname(self.pipe_in_loc), exist_ok=True)
            elif os.path.exists(self.pipe_in_loc):
                os.unlink(self.pipe_in_loc)
            os.mkfifo(self.pipe_in_loc)

        if self.create_pipe_out:
            if not os.path.exists(os.path.dirname(self.pipe_out_loc)):
                os.makedirs(os.path.dirname(self.pipe_out_loc), exist_ok=True)
            elif os.path.exists(self.pipe_out_loc):
                os.unlink(self.pipe_out_loc)
            os.mkfifo(self.pipe_out_loc)

        self._run()

        logger.debug("Opening pipe_in {}".format(self.pipe_in_loc))
        self.pipe_in = open(self.pipe_in_loc, "wb", buffering=0)
        logger.debug("Opening pipe_out {}".format(self.pipe_out_loc))
        self.pipe_out = open(self.pipe_out_loc, "rb", buffering=0)

        self.wait_for_ready()

    def stop(self):
        logger.debug("Stopping SEGrindRun {}".format(self.valgrind_pid))
        try:
            if self.is_running():
                self._send_cmd(SEMsgType.SEMSG_EXIT, None, 0.1)
        except BrokenPipeError:
            logger.debug("Error sending {} to {}".format(SEMsgType.SEMSG_EXIT.name, self.valgrind_pid))
            pass
        finally:
            # if self.valgrind_thread is not None:
            #     self.valgrind_thread.join(timeout=0.1)
            #     if self.valgrind_thread.is_alive():
            if self.valgrind_proc is not None:
                self.valgrind_proc.kill()
                if self.valgrind_proc.stdout is not None:
                    logger.debug("Closing valgrind_proc.stdout for {}".format(self.valgrind_pid))
                    self.valgrind_proc.stdout.close()
                if self.valgrind_proc.stderr is not None:
                    logger.debug("Closing valgrind_proc.stderr for {}".format(self.valgrind_pid))
                    self.valgrind_proc.stderr.close()
                if self.valgrind_proc.stdin is not None:
                    logger.debug("Closing valgrind_proc.stdin for {}".format(self.valgrind_pid))
                    self.valgrind_proc.stdin.close()
                self.valgrind_proc = None

            # if self.thr_r is not None:
            #     os.close(self.thr_r)
            #     self.thr_r = None
            # if self.thr_w is not None:
            #     os.close(self.thr_w)
            #     self.thr_w = None

            if self.log is not None:
                if not self.log.closed:
                    self.log.close()
                self.log = None

            if self.pipe_in is not None:
                logger.debug("Closing pipe_in for {}".format(self.valgrind_pid))
                self.pipe_in.close()
                self.pipe_in = None

            if self.create_pipe_in and os.path.exists(self.pipe_in_loc):
                os.unlink(self.pipe_in_loc)

            if self.pipe_out is not None:
                logger.debug("Closing pipe_out for {}".format(self.valgrind_pid))
                self.pipe_out.close()
                self.pipe_out = None

            if self.create_pipe_out and os.path.exists(self.pipe_out_loc):
                os.unlink(self.pipe_out_loc)

            logger.debug("SEGrindRun stopped for {}".format(self.valgrind_pid))

    def wait_for_ready(self, timeout=None):
        msg = self.read_response(timeout=timeout)

        if msg is None or msg.msgtype != SEMsgType.SEMSG_READY:
            error_msg = "Server did not issue a {} msg".format(SEMsgType.SEMSG_READY.name)
            if msg is not None:
                error_msg += ": {} (len = {})".format(msg.msgtype.name, msg.msglen)
            raise AssertionError(error_msg)
        logger.debug("Process {} is ready".format(self.valgrind_pid))

    def send_fuzz_cmd(self, timeout=None):
        return self._send_cmd(SEMsgType.SEMSG_FUZZ, None, timeout)

    def send_execute_cmd(self, timeout=None):
        return self._send_cmd(SEMsgType.SEMSG_EXECUTE, None, timeout)

    def send_reset_cmd(self, timeout=None):
        return self._send_cmd(SEMsgType.SEMSG_RESET, None, timeout)

    def send_coverage_cmd(self, timeout=None):
        return self._send_cmd(SEMsgType.SEMSG_COVERAGE, None, timeout)

    def clear_response_pipe(self):
        resp = self.read_response(0.1)
        while resp is not None:
            resp = self.read_response(0.1)

    def read_bytes_from_pipe(self, n, timeout=None):
        results = bytearray()
        if timeout is None:
            timeout = self.timeout

        while len(results) < n:
            if not self.is_running():
                raise AssertionError("Process {} not running".format(self.valgrind_pid))
            ready_pipes = select.select([self.pipe_out], [], [], timeout)
            if len(ready_pipes[0]) == 0:
                results = None
                break
            if self.pipe_out in ready_pipes[0]:
                tmp_pipe_data = self.pipe_out.read(n - len(results))
                if len(tmp_pipe_data) == 0:
                    results = None
                    break

                for b in tmp_pipe_data:
                    results.append(b)
        return results

    def read_response(self, timeout=None):
        if timeout is None:
            timeout = self.timeout
        result = None
        pipe_data = self.read_bytes_from_pipe(n=struct.calcsize(SEMessage.HEADER_FORMAT), timeout=timeout)
        if pipe_data is not None:
            header_data = struct.unpack_from(SEMessage.HEADER_FORMAT, pipe_data)
            msgtype = SEMsgType(header_data[0])
            msglen = header_data[1]

            if msglen > 0:
                data = self.read_bytes_from_pipe(n=msglen, timeout=timeout)
            else:
                data = None
            result = SEMessage(msgtype, data)

        if result is not None:
            logger.debug(
                "Received {} msg with {} bytes back from {}".format(result.msgtype.name, result.msglen,
                                                                    self.valgrind_pid))
        else:
            logger.debug("Received No message back from {}".format(self.valgrind_pid))
        return result

    def send_set_target_cmd(self, target, timeout=None):
        logger.debug("Setting target to {} for {}".format(hex(target), self.valgrind_pid))
        return self._send_cmd(SEMsgType.SEMSG_SET_TGT, struct.pack("Q", target), timeout=timeout)

    def send_set_ctx_cmd(self, io_vec):
        if io_vec is None:
            raise AssertionError("io_vec cannot be None")
        elif not isinstance(io_vec, IOVec):
            raise AssertionError("io_vec must be an instance of IOVec")

        data = io_vec.to_bytes()
        if len(data) == 0:
            raise AssertionError("IOVec is empty")

        return self._send_cmd(SEMsgType.SEMSG_SET_CTX, data)

    def get_latest_coverage(self):
        result = list()
        ack_msg = self.send_coverage_cmd()
        if ack_msg and ack_msg.msgtype == SEMsgType.SEMSG_ACK:
            resp_msg = self.read_response()
            if resp_msg and resp_msg.msgtype == SEMsgType.SEMSG_OK:
                data = io.BytesIO(resp_msg.data)
                result = bu.read_in_list(data)
        return result
