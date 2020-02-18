import os
import struct
import subprocess
from concurrent import futures

from .FBLogging import logger
from .FunctionDescriptor import FunctionDescriptor
from .IOVec import IOVec
from .PinRun import PinMessage, PinRun

WATCHDOG = 5.0
MAX_RETRY_COUNT = 3
MAX_ATTEMPTS = 100


class RunDesc:
    def __init__(self, func_desc, pin_loc, pintool_loc, loader_loc, work_dir, watchdog):
        self.func_desc = func_desc
        self.pin_loc = os.path.abspath(pin_loc)
        self.pintool_loc = os.path.abspath(pintool_loc)
        if loader_loc is not None:
            self.loader_loc = os.path.abspath(loader_loc)
        else:
            self.loader_loc = None
        self.work_dir = os.path.abspath(work_dir)
        self.watchdog = watchdog


class FuzzRunDesc(RunDesc):
    def __init__(self, func_desc, pin_loc, pintool_loc, loader_loc, work_dir, watchdog, fuzz_count,
                 attempt_count=MAX_ATTEMPTS):
        RunDesc.__init__(self, func_desc=func_desc, pin_loc=pin_loc, pintool_loc=pintool_loc, loader_loc=loader_loc,
                         work_dir=work_dir, watchdog=watchdog)
        self.fuzz_count = fuzz_count
        self.attempt_count = attempt_count


class ConsolidationRunDesc(RunDesc):
    def __init__(self, func_desc, pin_loc, pintool_loc, loader_loc, work_dir, watchdog, contexts):
        RunDesc.__init__(self, func_desc=func_desc, pin_loc=pin_loc, pintool_loc=pintool_loc, loader_loc=loader_loc,
                         work_dir=work_dir, watchdog=watchdog)
        self.contexts = contexts


class FuzzRunResult:
    def __init__(self, func_desc, io_vecs, coverage):
        self.func_desc = func_desc
        self.io_vecs = dict()
        self.coverages = dict()
        for io_vec in io_vecs:
            self.io_vecs[hash(io_vec)] = io_vec
            self.coverages[hash(io_vec)] = coverage[hash(io_vec)]

    def __len__(self):
        return len(self.io_vecs)


def read_coverage(resp_msg):
    curr_pos = resp_msg.data.tell()
    coveragesize = struct.unpack_from('N', resp_msg.data.getbuffer(), curr_pos)[0]
    coverage = list()
    resp_msg.data.seek(curr_pos + struct.calcsize('N'))
    for i in range(coveragesize):
        curr_pos = resp_msg.data.tell()
        (numInstructions, totalInstructions) = struct.unpack_from('NN', resp_msg.data.getbuffer(), curr_pos)
        resp_msg.data.seek(curr_pos + struct.calcsize('NN'))

        instructionAddrs = list()
        curr_pos = resp_msg.data.tell()
        fmt = 'P' * numInstructions
        instructions = struct.unpack_from(fmt, resp_msg.data.getbuffer(), curr_pos)
        resp_msg.data.seek(curr_pos + struct.calcsize(fmt))
        for addr in instructions:
            instructionAddrs.append(addr)
        instructionAddrs.sort()
        coverage.append((instructionAddrs, totalInstructions))

    return coverage


def find_funcs(binary, target=None, ignored_funcs=None, is_shared=None):
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


def fuzz_one_function(fuzz_desc):
    pin_run = None
    func_name = fuzz_desc.func_desc.name
    target = fuzz_desc.func_desc.location
    binary = fuzz_desc.func_desc.binary
    successful_contexts = set()
    coverages = dict()

    try:
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
        # cmd_log = os.path.abspath("/dev/null")
        if not os.path.exists(os.path.dirname(log_out)):
            os.makedirs(os.path.dirname(log_out), exist_ok=True)

        logger.debug("Creating PinRun for {}".format(run_name))
        pin_run = PinRun(fuzz_desc.pin_loc, fuzz_desc.pintool_loc, binary, fuzz_desc.loader_loc, pipe_in=pipe_in,
                         pipe_out=pipe_out, log_loc=log_out, cwd=fuzz_desc.work_dir, cmd_log_loc=cmd_log)
        logger.debug("Done")
        fuzz_count = 0
        attempts = 0

        while fuzz_count < fuzz_desc.fuzz_count:
            attempts += 1
            if attempts > fuzz_desc.attempt_count:
                raise RuntimeError("Too many attempts for {}".format(run_name))

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
                    io_vec = IOVec(result.data)
                    io_vec_coverage = read_coverage(result)

                    successful_contexts.add(io_vec)
                    coverages[hash(io_vec)] = io_vec_coverage
                    fuzz_count += 1
                    logger.info("{} created {} ({} of {})".format(run_name, io_vec.hexdigest(), fuzz_count,
                                                                  fuzz_desc.fuzz_count))
                elif result is not None and len(result.data.getbuffer()) > 0:
                    logger.debug("Fuzzing run failed: {}".format(result.data.getvalue()))
                elif result is None:
                    logger.debug("Fuzzing result is None")
                elif result is not None and len(result.data.getbuffer()) == 0:
                    logger.debug("Fuzzing data is zero")
                elif result.msgtype != PinMessage.ZMSG_OK:
                    logger.debug("Pin message is not OK: %s".format(result))
            except TimeoutError as e:
                logger.debug(str(e))
                pin_run.stop()
                continue
            except AssertionError as e:
                logger.debug(str(e))
                pin_run.stop()
                continue
            except KeyboardInterrupt:
                logger.debug("{} received KeyboardInterrupt".format(run_name))
                pin_run.stop()
                continue
    except Exception as e:
        logger.debug("Error for {}: {}".format(run_name, e))
    finally:
        logger.info("Finished {}".format(run_name))
        pin_run.stop()
        if os.path.exists(pipe_in):
            os.unlink(pipe_in)
        if os.path.exists(pipe_out):
            os.unlink(pipe_out)
        del pin_run
        return FuzzRunResult(fuzz_desc.func_desc, successful_contexts, coverages)


def fuzz_functions(func_descs, pin_loc, pintool_loc, loader_loc, num_threads, watchdog=WATCHDOG, fuzz_count=5,
                   work_dir=os.path.abspath(os.path.join(os.curdir, "_work"))):
    fuzz_runs = list()
    io_vecs_dict = dict()
    unclassified = set()

    if not os.path.exists(work_dir):
        os.makedirs(work_dir, exist_ok=True)

    for func_desc in func_descs:
        fuzz_runs.append(FuzzRunDesc(func_desc, pin_loc, pintool_loc, loader_loc, work_dir, watchdog, fuzz_count))

    with futures.ThreadPoolExecutor(max_workers=num_threads) as pool:
        results = {pool.submit(fuzz_one_function, fuzz_run): fuzz_run for fuzz_run in fuzz_runs}
        for result in futures.as_completed(results):
            fuzz_run = results[result]
            try:
                fuzz_run_result = result.result()
                if len(fuzz_run_result) > 0:
                    io_vecs_dict[fuzz_run.func_desc] = fuzz_run_result
                else:
                    unclassified.add(fuzz_run.func_desc)
            except Exception as e:
                continue

    return io_vecs_dict, unclassified


def consolidate_one_function(consolidationRunDesc):
    func_desc = consolidationRunDesc.func_desc

    work_dir = os.path.join(consolidationRunDesc.work_dir, "consolidate")
    log_dir = os.path.join("logs", "consolidate")

    run_name = os.path.basename(func_desc.binary) + "." + func_desc.name + "." + str(func_desc.location)
    pipe_in = os.path.abspath(os.path.join(work_dir, run_name + ".in"))
    pipe_out = os.path.abspath(os.path.join(work_dir, run_name + ".out"))
    log_loc = os.path.abspath(os.path.join(log_dir, run_name + ".consol.log"))
    cmd_log_loc = os.path.abspath(os.path.join(log_dir, run_name + ".consol.cmd.log"))
    # cmd_log_loc = os.path.abspath("/dev/null")

    desc_map = dict()

    if not os.path.exists(work_dir):
        os.makedirs(work_dir, exist_ok=True)
    if not os.path.exists(log_dir):
        os.makedirs(log_dir, exist_ok=True)

    logger.info("{} starting".format(run_name))
    pin_run = PinRun(consolidationRunDesc.pin_loc, consolidationRunDesc.pintool_loc, func_desc.binary,
                     consolidationRunDesc.loader_loc, pipe_in, pipe_out, log_loc,
                     os.path.abspath(work_dir), cmd_log_loc)
    ctx_count = 0
    retry_count = 0
    idx = 0
    logger.debug("Created pin run for {}".format(run_name))
    while idx < len(consolidationRunDesc.contexts):
        iovec = consolidationRunDesc.contexts[idx]
        if retry_count > MAX_RETRY_COUNT:
            idx += 1
            retry_count = 0
            logger.error("{} failed to properly execute {}".format(run_name, iovec.hexdigest()))
            continue

        logger.info("{} testing {}".format(run_name, iovec.hexdigest()))
        try:
            if not pin_run.is_running():
                logger.debug("Starting pin_run for {}".format(run_name))
                pin_run.stop()
                pin_run.start(timeout=consolidationRunDesc.watchdog)

                if consolidationRunDesc.loader_loc is None:
                    ack_msg = pin_run.send_set_target_cmd(func_desc.location, timeout=consolidationRunDesc.watchdog)
                else:
                    ack_msg = pin_run.send_set_target_cmd(func_desc.name, timeout=consolidationRunDesc.watchdog)

                if ack_msg is None or ack_msg.msgtype != PinMessage.ZMSG_ACK:
                    logger.error("Set target ACK not received for {}".format(run_name))
                    break
                resp_msg = pin_run.read_response(timeout=consolidationRunDesc.watchdog)
                if resp_msg is None or resp_msg.msgtype != PinMessage.ZMSG_OK:
                    logger.error("Could not set target for {}".format(run_name))
                    break
                logger.debug("pin run started for {}".format(run_name))
                ctx_count = 0
            ctx_count += 1

            logger.debug("Sending reset command for {}".format(run_name))
            ack_msg = pin_run.send_reset_cmd(timeout=consolidationRunDesc.watchdog)
            if ack_msg is None or ack_msg.msgtype != PinMessage.ZMSG_ACK:
                pin_run.stop()
                retry_count += 1
                logger.error("Reset ACK not received for {}".format(run_name))
                continue
            resp_msg = pin_run.read_response(timeout=consolidationRunDesc.watchdog)
            if resp_msg is None or resp_msg.msgtype != PinMessage.ZMSG_OK:
                pin_run.stop()
                retry_count += 1
                logger.error("Could not reset for {}".format(run_name))
                if resp_msg is None:
                    logger.error("{} Received no response back".format(run_name))
                else:
                    logger.error("{} Received {} message".format(run_name, PinMessage.names[resp_msg.msgtype]))
                continue

            logger.debug("Sending set ctx command for {}".format(run_name))
            ack_msg = pin_run.send_set_ctx_cmd(iovec, timeout=consolidationRunDesc.watchdog)
            if ack_msg is None or ack_msg.msgtype != PinMessage.ZMSG_ACK:
                pin_run.stop()
                retry_count += 1
                logger.error("Set Context ACK not received for {}".format(run_name))
                continue
            resp_msg = pin_run.read_response(timeout=consolidationRunDesc.watchdog)
            if resp_msg is None or resp_msg.msgtype != PinMessage.ZMSG_OK:
                pin_run.stop()
                retry_count += 1
                logger.error("Could not set context for {}".format(run_name))
                continue

            logger.debug("Sending execute command for {}".format(run_name))
            ack_msg = pin_run.send_execute_cmd(timeout=consolidationRunDesc.watchdog)
            if ack_msg is None or ack_msg.msgtype != PinMessage.ZMSG_ACK:
                pin_run.stop()
                retry_count += 1
                logger.error("Set Context ACK not received for {}".format(run_name))
                continue

            resp_msg = pin_run.read_response(timeout=consolidationRunDesc.watchdog)
            if resp_msg is not None and resp_msg.msgtype == PinMessage.ZMSG_OK:
                coverage = read_coverage(resp_msg)
                desc_map[hash(iovec)] = (func_desc, coverage)
                logger.info("{} accepts {} ({})".format(run_name, iovec.hexdigest(), ctx_count))
            else:
                logger.info("{} rejects {} ({})".format(run_name, iovec.hexdigest(), ctx_count))
            idx += 1
            retry_count = 0
        except AssertionError as e:
            logger.debug("Error for {}: {}".format(run_name, str(e)))
            logger.info("{} rejects {} ({})".format(run_name, iovec.hexdigest(), ctx_count))
            idx += 1
            pin_run.stop()
            continue
        except Exception as e:
            logger.exception("Error for {}: {}".format(run_name, str(e)))
            break

    pin_run.stop()
    del pin_run
    if os.path.exists(pipe_in):
        os.unlink(pipe_in)
    if os.path.exists(pipe_out):
        os.unlink(pipe_out)
    logger.info("Finished {}".format(run_name))
    return desc_map


def consolidate_contexts(pin_loc, pintool_loc, loader_loc, num_threads, contexts_mapping, watchdog=WATCHDOG,
                         work_dir=os.path.abspath(os.path.join(os.curdir, "_work"))):
    desc_map = dict()

    if not os.path.exists(work_dir):
        os.makedirs(work_dir, exist_ok=True)

    consolidation_runs = list()
    for func_desc, contexts in contexts_mapping.items():
        consolidation_runs.append(ConsolidationRunDesc(func_desc, pin_loc, pintool_loc, loader_loc, work_dir,
                                                       watchdog, contexts))

    with futures.ThreadPoolExecutor(max_workers=num_threads) as pool:
        results = {pool.submit(consolidate_one_function, consolidation_run): consolidation_run for consolidation_run in
                   consolidation_runs}
        for result in futures.as_completed(results):
            try:
                consolidation_mapping = result.result()
                for hash_sum, (func_desc, coverage) in consolidation_mapping.items():
                    if hash_sum not in desc_map:
                        desc_map[hash_sum] = dict()
                    desc_map[hash_sum][func_desc] = coverage
            except Exception as e:
                logger.exception(e)
                continue

    return desc_map
