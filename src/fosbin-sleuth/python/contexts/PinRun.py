import os
import subprocess
from .FBLogging import logger


class PinRun:
    def __init__(self, pin_loc, pintool_loc, binary_loc, target, loader_loc=None):
        self.binary_loc = os.path.abspath(binary_loc)

        try:
            self.target = hex(int(target, 16))
        except Exception:
            self.target = target

        self.pin_loc = os.path.abspath(pin_loc)
        self.pintool_loc = os.path.abspath(pintool_loc)
        if loader_loc is not None:
            self.loader_loc = os.path.abspath(loader_loc)

        self.fuzz_count = 0
        self.log_loc = None
        self.accepted_contexts = list()

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

    def generate_cmd(self):
        cmd = [self.pin_loc, "-t", self.pintool_loc]

        if self.log_loc is not None:
            cmd.append("-out")
            cmd.append(os.path.abspath(self.log_loc))

        if self.out_contexts is not None:
            cmd.append("-ctx-out")
            cmd.append(os.path.abspath(self.out_contexts))

        if os.path.splitext(self.binary_loc)[1] == ".so":
            cmd.append("-shared-func")
            cmd.append(self.target)
        else:
            cmd.append("-target")
            cmd.append(hex(self.target))

        cmd.append("--")

        if os.path.splitext(self.binary_loc)[1] == ".so":
            cmd.append(self.loader_loc)
            cmd.append(self.binary_loc)
        else:
            cmd.append(self.binary_loc)

        return cmd

    def execute_cmd(self, cwd=os.getcwd(), capture_out=False):
        self._check_state()
        cmd = self.generate_cmd()

        full_cmd = list()
        if self.total_time is not None:
            full_cmd.append("timeout")
            full_cmd.append("-k")
            full_cmd.append("1")
            full_cmd.append(str(self.total_time - 2))

        for cmd_token in cmd:
            full_cmd.append(cmd_token)

        logger.info("Running {}".format(" ".join(full_cmd)))

        try:
            self.completed_proc = subprocess.run(full_cmd, timeout=self.total_time, cwd=os.path.abspath(cwd),
                                                 capture_output=capture_out)
            self.process_timedout = False
        except subprocess.TimeoutExpired as e:
            self.process_timedout = True
            raise e

    def returncode(self):
        if self.completed_proc is not None:
            return self.completed_proc.returncode
        return None
