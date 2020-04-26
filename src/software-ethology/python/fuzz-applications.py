import argparse
import io
import logging
import multiprocessing as mp
import os
import pickle
import time

import contexts.binaryutils as bu
from contexts.FBLogging import logger
from contexts.IOVec import IOVec
from contexts.SEGrindRun import SEGrindRun, SEMsgType

MAX_ATTEMPTS = 25
WATCHDOG = 50.0
DEFAULT_DURATION = 5 * 60 * 60


# class FuzzRunResult:
#     def __init__(self, func_desc, io_vecs, coverage):
#         self.func_desc = func_desc
#         self.io_vecs = dict()
#         self.coverages = dict()
#         for io_vec in io_vecs:
#             self.io_vecs[hash(io_vec)] = io_vec
#             # self.coverages[hash(io_vec)] = coverage[hash(io_vec)]
# 
#     def __len__(self):
#         return len(self.io_vecs)


class FuzzRunDesc(bu.RunDesc):
    def __init__(self, func_desc, valgrind_loc, work_dir, watchdog, attempt_count=MAX_ATTEMPTS):
        bu.RunDesc.__init__(self, func_desc=func_desc, valgrind_loc=valgrind_loc, work_dir=work_dir, watchdog=watchdog)
        self.attempt_count = attempt_count


def coverage_is_different(base_coverage, new_coverage):
    if len(base_coverage) != len(new_coverage):
        return True
    for idx in range(len(base_coverage)):
        if base_coverage[idx] != new_coverage[idx]:
            return True

    return False


def fuzz_one_function(fuzz_desc, io_vec_list, coverage_map, duration, sema):
    segrind_run = None
    func_name = fuzz_desc.func_desc.name
    target = fuzz_desc.func_desc.location
    binary = fuzz_desc.func_desc.binary

    try:
        run_name = "{}.{}.{}".format(os.path.basename(binary), func_name, target)
        logger.debug("{} target is {} ({})".format(run_name, hex(target), func_name))
        pipe_in = os.path.join(fuzz_desc.work_dir, run_name + ".in")
        pipe_out = os.path.join(fuzz_desc.work_dir, run_name + ".out")
        log_names = bu.get_log_names(fuzz_desc.func_desc)
        log_out = os.path.join("logs", "fuzz", log_names[0])
        cmd_log = os.path.join("logs", "fuzz", log_names[1])
        # cmd_log = os.path.abspath("/dev/null")
        if not os.path.exists(os.path.dirname(log_out)):
            os.makedirs(os.path.dirname(log_out), exist_ok=True)

        logger.debug("Creating SEGrindRun for {}".format(run_name))
        segrind_run = SEGrindRun(valgrind_loc=fuzz_desc.valgrind_loc, binary_loc=binary, pipe_in=pipe_in,
                                 pipe_out=pipe_out, valgrind_log_loc=log_out, run_log_loc=cmd_log,
                                 cwd=fuzz_desc.work_dir, timeout=fuzz_desc.watchdog)
        logger.debug("Done")

        start_time = time.time()
        current_iovec_idx = 0
        has_sema = False

        while time.time() < start_time + duration or len(io_vec_list) > current_iovec_idx:
            try:
                sema.acquire()
                has_sema = True
                if not segrind_run.is_running():
                    logger.info("Starting SEGrindRun for {}".format(run_name))
                    segrind_run.start()
                    ack_msg = segrind_run.send_set_target_cmd(target)
                    if ack_msg is None or ack_msg.msgtype != SEMsgType.SEMSG_ACK:
                        raise RuntimeError("Could not set target {}".format(target))

                    resp_msg = segrind_run.read_response()
                    if resp_msg is None or resp_msg.msgtype != SEMsgType.SEMSG_OK:
                        raise RuntimeError("Could not set target {}".format(target))

                resp_msg = None
                result = None
                using_external_iovec = False
                using_internal_iovec = False
                io_vec = None
                if len(io_vec_list) > current_iovec_idx:
                    while current_iovec_idx < len(io_vec_list):
                        if io_vec_list[current_iovec_idx] not in coverage_map[fuzz_desc.func_desc]:
                            io_vec = io_vec_list[current_iovec_idx]
                            current_iovec_idx += 1
                            break
                        current_iovec_idx += 1
                    if io_vec is not None:
                        ack_msg = segrind_run.send_set_ctx_cmd(io_vec)
                        if ack_msg and ack_msg.msgtype == SEMsgType.SEMSG_ACK:
                            resp_msg = segrind_run.read_response()
                        ready_to_run = (resp_msg is not None and resp_msg.msgtype == SEMsgType.SEMSG_OK)
                        using_external_iovec = ready_to_run
                else:
                    if len(coverage_map[fuzz_desc.func_desc]) > 0:
                        max_coverage = 0
                        for iov, coverage in coverage_map[fuzz_desc.func_desc].items():
                            if len(coverage) > max_coverage:
                                io_vec = iov
                                max_coverage = len(coverage)

                        logger.debug("IOVec chosen: {}".format(str(io_vec)))
                        ack_msg = segrind_run.send_set_ctx_cmd(io_vec)
                        if ack_msg and ack_msg.msgtype == SEMsgType.SEMSG_ACK:
                            resp_msg = segrind_run.read_response()
                            if resp_msg and resp_msg.msgtype == SEMsgType.SEMSG_OK:
                                using_internal_iovec = True

                    ack_msg = segrind_run.send_fuzz_cmd()
                    if ack_msg and ack_msg.msgtype == SEMsgType.SEMSG_ACK:
                        resp_msg = segrind_run.read_response()
                    ready_to_run = (resp_msg and resp_msg.msgtype == SEMsgType.SEMSG_OK)

                if ready_to_run:
                    ack_msg = segrind_run.send_execute_cmd()
                    if ack_msg and ack_msg.msgtype == SEMsgType.SEMSG_ACK:
                        result = segrind_run.read_response()

                if ready_to_run and result is None:
                    logger.debug("Fuzzing result is None for {}".format(run_name))
                elif ready_to_run and result.msgtype == SEMsgType.SEMSG_OK:
                    try:
                        coverage = segrind_run.get_latest_coverage()
                        logger.debug("{} recorded {} instructions".format(run_name, len(coverage)))
                        if not using_external_iovec and not using_internal_iovec:
                            logger.debug("Reading in IOVec from {}".format(segrind_run.valgrind_pid))
                            io_vec = IOVec(result.data)
                            logger.info("{} created {}".format(run_name, str(io_vec)))
                            io_vec_contents = io.StringIO()
                            io_vec.pretty_print(out=io_vec_contents)
                            logger.debug(io_vec_contents.getvalue())
                            addr_str = ""
                            for addr in coverage:
                                addr_str += hex(addr) + " "
                            logger.debug("New coverage added: {}".format(addr_str))
                            coverage_map[fuzz_desc.func_desc][io_vec] = coverage
                            io_vec_list.append(io_vec)
                        elif using_internal_iovec:
                            base_iovec = io_vec
                            io_vec = IOVec(result.data)
                            base_coverage = coverage_map[fuzz_desc.func_desc][base_iovec]
                            if coverage_is_different(base_coverage, coverage):
                                logger.info("{} created {}".format(run_name, str(io_vec)))
                                coverage_map[fuzz_desc.func_desc][io_vec] = coverage
                                io_vec_list.append(io_vec)
                        elif using_external_iovec:
                            logger.debug('{} accepted {}'.format(run_name, str(io_vec)))
                            coverage_map[fuzz_desc.func_desc][io_vec] = coverage
                    except Exception as e:
                        logger.error("{} failed to add IOVec: {}".format(run_name, str(e)))
                elif ready_to_run and result.msgtype != SEMsgType.SEMSG_OK:
                    if using_external_iovec:
                        logger.debug("{} rejects {}".format(run_name, str(io_vec)))

                sema.release()
                has_sema = False
                if len(io_vec_list) <= current_iovec_idx:
                    time.sleep(1)
            except TimeoutError as e:
                logger.debug(str(e))
                segrind_run.stop()
                if has_sema:
                    sema.release()
                    has_sema = False
                continue
            except AssertionError as e:
                logger.debug(str(e))
                segrind_run.stop()
                if has_sema:
                    sema.release()
                    has_sema = False
                continue
            except KeyboardInterrupt:
                logger.debug("{} received KeyboardInterrupt".format(run_name))
                if has_sema:
                    sema.release()
                    has_sema = False
                segrind_run.stop()
                continue
    except Exception as e:
        if has_sema:
            sema.release()
            has_sema = False
        logger.error("Error for {}: {}".format(run_name, e))
    finally:
        if has_sema:
            sema.release()
            has_sema = False
        logger.info("Finished {}".format(run_name))
        segrind_run.stop()
        if os.path.exists(pipe_in):
            os.unlink(pipe_in)
        if os.path.exists(pipe_out):
            os.unlink(pipe_out)
        del segrind_run


def fuzz_functions(func_descs, valgrind_loc, watchdog, duration, thread_count,
                   work_dir=os.path.abspath(os.path.join(os.curdir, "_work"))):
    fuzz_runs = list()
    unclassified = set()
    io_vecs_dict = dict()

    if not os.path.exists(work_dir):
        os.makedirs(work_dir, exist_ok=True)

    for func_desc in func_descs:
        fuzz_runs.append(FuzzRunDesc(func_desc, valgrind_loc, work_dir, watchdog))

    with mp.Manager() as manager:
        generated_iovecs = manager.list()
        iovec_coverage = manager.dict()
        sema = mp.Semaphore(thread_count)

        for func_desc in func_descs:
            iovec_coverage[func_desc] = manager.dict()

        processes = list()
        for fuzz_run in fuzz_runs:
            processes.append(
                mp.Process(target=fuzz_one_function,
                           args=(fuzz_run, generated_iovecs, iovec_coverage, duration, sema,)))

        for p in processes:
            p.start()

        for p in processes:
            p.join()

        for func_desc, coverages in iovec_coverage.items():
            io_vecs_dict[func_desc] = dict()
            for io_vec, coverage in coverages.items():
                io_vecs_dict[func_desc][io_vec] = coverage

    for func_desc in func_descs:
        if len(io_vecs_dict[func_desc]) == 0:
            unclassified.add(func_desc)

    return io_vecs_dict, unclassified


def main():
    global DEFAULT_DURATION, WATCHDOG

    parser = argparse.ArgumentParser(description="Generate input/output vectors")
    parser.add_argument("-valgrind", help="/path/to/pin-3.11/dir", required=True)
    parser.add_argument("-bin", help="/path/to/target/application", required=True)
    parser.add_argument("-ignore", help="/path/to/ignored/functions")
    parser.add_argument("-funcs", help="/path/to/file/with/func/names")
    parser.add_argument("-log", help="/path/to/log/file", default="fuzz.log")
    parser.add_argument("-loglevel", help="Level of output", type=int, default=logging.INFO)
    parser.add_argument("-threads", help="Number of threads to use", type=int, default=mp.cpu_count())
    parser.add_argument('-o', '--out', help="/path/to/output/fuzzing/results", default="out.desc")
    parser.add_argument("-timeout", help='Number of seconds to wait per run', type=int, default=WATCHDOG)
    parser.add_argument('-duration', help='Total number of seconds to fuzz targets', type=int, default=DEFAULT_DURATION)

    results = parser.parse_args()

    if results.loglevel not in [logging.DEBUG, logging.INFO, logging.CRITICAL, logging.ERROR]:
        logger.fatal("Invalid loglevel: {}".format(results.loglevel))
        exit(1)

    if results.timeout <= 0:
        logger.fatal("Invalid timeout: {}".format(results.timeout))
        exit(1)

    if results.duration <= 0:
        logger.fatal("Invalid duration: {}".format(results.duration))
        exit(1)

    if results.threads <= 0:
        logger.fatal("Invalid thread count: {}".format(results.threads))
        exit(1)

    logger.setLevel(results.loglevel)
    logfile = os.path.abspath(results.log)
    if logfile is not None:
        if not os.path.exists(os.path.dirname(logfile)):
            os.makedirs(os.path.dirname(logfile), exist_ok=True)
        logger.addHandler(logging.FileHandler(logfile, mode="w"))

    if not os.path.exists(results.bin):
        logger.fatal("Could not find {}".format(results.bin))
        exit(1)

    if not os.path.exists(results.valgrind):
        logger.fatal("Could not find valgrind {}".format(results.valgrind))
        exit(1)

    valgrind_loc = os.path.abspath(results.valgrind)

    ignored_funcs = set()

    if results.ignore is not None:
        logger.debug("Reading ignored functions")
        with open(results.ignore) as f:
            for line in f.readlines():
                line = line.strip()
                ignored_funcs.add(line)
        logger.debug("done")

    if results.funcs is not None:
        logger.info("Finding specified functions")
        location_map = dict()
        with open(results.funcs, "r") as f:
            for line in f.readlines():
                line = line.strip()
                temp = bu.find_funcs(results.bin, line, ignored_funcs)
                for loc, func_desc in temp.items():
                    location_map[loc] = func_desc
    else:
        logger.debug("Reading functions to fuzz")
        location_map = bu.find_funcs(results.bin, ignored_funcs=ignored_funcs)
    logger.debug("done")

    out_file = os.path.abspath(results.out)
    if not os.path.exists(os.path.dirname(out_file)):
        os.makedirs(os.path.dirname(out_file), exist_ok=True)

    args = list()
    logger.debug("Building fuzz target list")
    func_count = len(location_map)
    for location, func_desc in location_map.items():
        args.append(func_desc)
    logger.debug("done")
    logger.info("Fuzzing {} targets".format(len(args)))

    if len(args) > 0:
        (fuzz_run_results, unclassified) = fuzz_functions(args, valgrind_loc=valgrind_loc, watchdog=results.timeout,
                                                          duration=results.duration, thread_count=results.threads)

        logger.info("{} has {} functions".format(results.bin, func_count))
        logger.info("Fuzzable functions: {}".format(len(fuzz_run_results)))
        if len(unclassified) > 0:
            logger.info("Unclassified functions:")
            for func_desc in unclassified:
                logger.info(func_desc.name)

        with open(out_file, "wb") as f:
            pickle.dump(fuzz_run_results, f)
    else:
        logger.fatal("Could not find any functions to fuzz")


if __name__ == "__main__":
    main()
