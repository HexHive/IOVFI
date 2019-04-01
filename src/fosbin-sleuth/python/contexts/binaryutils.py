import os
import subprocess
from concurrent import futures

from .FBLogging import logger
from .FunctionDescriptor import FunctionDescriptor
from .IOVec import IOVec
from .PinRun import PinMessage, PinRun


def find_funcs(binary, target=None, ignored_funcs=None):
    target_is_name = True
    if target is not None:
        try:
            target = int(target, 16)
            target_is_name = False
        except Exception:
            pass
    location_map = dict()
    readelf_cmd = subprocess.run(['readelf', '-Ws', binary], stdout=subprocess.PIPE)
    lines = readelf_cmd.stdout.split(b'\n')
    for line in lines:
        line = line.decode('utf-8')
        toks = line.split()
        if len(toks) > 4 and toks[3] == "FUNC":
            loc = int(toks[1], 16)
            name = toks[-1]
            if '@' in name:
                name = name[:name.find("@")]

            if ignored_funcs is not None and (name in ignored_funcs or loc in ignored_funcs):
                continue
            if target is None or (not target_is_name and target == loc) or (target_is_name and target == name):
                location_map[loc] = FunctionDescriptor(binary, name, loc)
    return location_map


class FuzzRunDesc:
    def __init__(self, func_desc, pin_loc, pintool_loc, loader_loc, work_dir, watchdog, fuzz_count):
        self.func_desc = func_desc
        self.pin_loc = os.path.abspath(pin_loc)
        self.pintool_loc = os.path.abspath(pintool_loc)
        self.loader_loc = os.path.abspath(loader_loc)
        self.work_dir = os.path.abspath(work_dir)
        self.watchdog = watchdog
        self.fuzz_count = fuzz_count


def fuzz_one_function(fuzz_desc):
    func_name = fuzz_desc.func_desc.name
    target = fuzz_desc.func_desc.location
    binary = fuzz_desc.func_desc.binary
    successful_contexts = set()

    if os.path.splitext(binary)[1] == ".so":
        target = func_name

    run_name = "{}.{}.{}".format(os.path.basename(binary), func_name, target)
    if fuzz_desc.loader_loc is None:
        logger.debug("{} target is {}".format(run_name, hex(target)))
    else:
        logger.debug("{} target is {}".format(run_name, target))
    pipe_in = os.path.join(fuzz_desc.work_dir, run_name + ".in")
    pipe_out = os.path.join(fuzz_desc.work_dir, run_name + ".out")
    log_out = os.path.join("logs", "fuzz", run_name + ".log")
    cmd_log = os.path.join("logs", "fuzz", run_name + ".cmd.log")
    if not os.path.exists(os.path.dirname(log_out)):
        os.makedirs(os.path.dirname(log_out), exist_ok=True)

    logger.debug("Creating PinRun for {}".format(run_name))
    pin_run = PinRun(fuzz_desc.pin_loc, fuzz_desc.pintool_loc, binary, fuzz_desc.loader_loc, pipe_in=pipe_in,
                     pipe_out=pipe_out, log_loc=log_out, cwd=fuzz_desc.work_dir, cmd_log_loc=cmd_log)
    logger.debug("Done")
    try:
        for x in range(fuzz_desc.fuzz_count):
            try:
                if not pin_run.is_running():
                    logger.debug("Starting PinRun for {}".format(run_name))
                    pin_run.start()
                    ack_msg = pin_run.send_set_target_cmd(target, fuzz_desc.watchdog)
                    if ack_msg is None or ack_msg.msgtype != PinMessage.ZMSG_ACK:
                        raise RuntimeError("Could not set target {}".format(target))

                    resp_msg = pin_run.read_response(timeout=fuzz_desc.watchdog)
                    if resp_msg is None or resp_msg.msgtype != PinMessage.ZMSG_OK:
                        raise RuntimeError("Could not set target {}".format(target))

                ack_msg = pin_run.send_reset_cmd(timeout=fuzz_desc.watchdog)
                if ack_msg is None or ack_msg.msgtype != PinMessage.ZMSG_ACK:
                    continue

                resp_msg = pin_run.read_response(timeout=fuzz_desc.watchdog)
                if resp_msg is None or resp_msg.msgtype \
                        != PinMessage.ZMSG_OK:
                    continue

                ack_msg = pin_run.send_fuzz_cmd(timeout=fuzz_desc.watchdog)
                if ack_msg is None or ack_msg.msgtype != PinMessage.ZMSG_ACK:
                    continue
                resp_msg = pin_run.read_response(timeout=fuzz_desc.watchdog)
                if resp_msg is None or resp_msg.msgtype != PinMessage.ZMSG_OK:
                    continue

                ack_msg = pin_run.send_execute_cmd(timeout=fuzz_desc.watchdog)
                if ack_msg is None or ack_msg.msgtype != PinMessage.ZMSG_ACK:
                    continue

                result = pin_run.read_response(timeout=fuzz_desc.watchdog)
                if result is not None and result.msgtype == PinMessage.ZMSG_OK:
                    successful_contexts.add(IOVec(result.data))
                elif result is not None and len(result.data.getbuffer()) > 0:
                    logger.info("Fuzzing run failed: {}".format(result.data.getvalue()))
            except TimeoutError as e:
                logger.exception(str(e))
                pin_run.stop()
                continue
            except AssertionError as e:
                logger.exception(str(e))
                pin_run.stop()
                continue

    except Exception as e:
        logger.exception("Error for {}: {}".format(run_name, e))
    finally:
        logger.info("Finished {}".format(run_name))
        pin_run.stop()
        if os.path.exists(pipe_in):
            os.unlink(pipe_in)
        if os.path.exists(pipe_out):
            os.unlink(pipe_out)
        del pin_run
        return successful_contexts


def fuzz_functions(func_descs, pin_loc, pintool_loc, loader_loc, num_threads, watchdog=5.0, fuzz_count=5,
                   work_dir=os.path.abspath(os.path.join(os.curdir, "_work"))):
    fuzz_runs = list()
    io_vecs_dict = dict()

    if not os.path.exists(work_dir):
        os.makedirs(work_dir, exist_ok=True)

    for func_desc in func_descs:
        fuzz_runs.append(FuzzRunDesc(func_desc, pin_loc, pintool_loc, loader_loc, work_dir, watchdog, fuzz_count))

    with futures.ThreadPoolExecutor(max_workers=num_threads) as pool:
        results = {pool.submit(fuzz_one_function, fuzz_run): fuzz_run for fuzz_run in fuzz_runs}
        for result in futures.as_completed(results):
            fuzz_run = results[result]
            try:
                io_vecs = result.result()
                if len(io_vecs) > 0:
                    io_vecs_dict[fuzz_run] = io_vecs
            except Exception as e:
                continue

    return io_vecs_dict
