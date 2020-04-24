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
DEFAULT_DURATION = 10 * 60


class FuzzRunResult:
    def __init__(self, func_desc, io_vecs, coverage):
        self.func_desc = func_desc
        self.io_vecs = dict()
        self.coverages = dict()
        for io_vec in io_vecs:
            self.io_vecs[hash(io_vec)] = io_vec
            # self.coverages[hash(io_vec)] = coverage[hash(io_vec)]

    def __len__(self):
        return len(self.io_vecs)


class FuzzRunDesc(bu.RunDesc):
    def __init__(self, func_desc, valgrind_loc, work_dir, watchdog, attempt_count=MAX_ATTEMPTS):
        bu.RunDesc.__init__(self, func_desc=func_desc, valgrind_loc=valgrind_loc, work_dir=work_dir, watchdog=watchdog)
        self.attempt_count = attempt_count


def fuzz_one_function(fuzz_desc, io_vec_list, coverage_map, duration):
    segrind_run = None
    func_name = fuzz_desc.func_desc.name
    target = fuzz_desc.func_desc.location
    binary = fuzz_desc.func_desc.binary
    successful_contexts = set()
    coverages = dict()

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

        while time.time() < start_time + duration:
            try:
                if not segrind_run.is_running():
                    logger.info("Starting SEGrindRun for {}".format(run_name))
                    segrind_run.start()
                    ack_msg = segrind_run.send_set_target_cmd(target, fuzz_desc.watchdog)
                    if ack_msg is None or ack_msg.msgtype != SEMsgType.SEMSG_ACK:
                        raise RuntimeError("Could not set target {}".format(target))

                    resp_msg = segrind_run.read_response()
                    if resp_msg is None or resp_msg.msgtype != SEMsgType.SEMSG_OK:
                        raise RuntimeError("Could not set target {}".format(target))

                resp_msg = None
                result = None
                using_existing_iovec = False
                io_vec = None
                if len(io_vec_list) > current_iovec_idx:
                    while current_iovec_idx < len(io_vec_list):
                        if io_vec_list[current_iovec_idx] not in successful_contexts:
                            io_vec = io_vec_list[current_iovec_idx]
                            current_iovec_idx += 1
                            break
                        current_iovec_idx += 1
                    if io_vec is not None:
                        ack_msg = segrind_run.send_set_ctx_cmd(io_vec)
                        if ack_msg and ack_msg.msgtype == SEMsgType.SEMSG_ACK:
                            resp_msg = segrind_run.read_response()
                        ready_to_run = (resp_msg is not None and resp_msg.msgtype == SEMsgType.SEMSG_OK)
                        using_existing_iovec = ready_to_run
                elif len(successful_contexts) > 0:
                    idx = rand
                else:
                    ack_msg = segrind_run.send_fuzz_cmd()
                    if ack_msg and ack_msg.msgtype == SEMsgType.SEMSG_ACK:
                        resp_msg = segrind_run.read_response()
                    ready_to_run = (resp_msg and resp_msg.msgtype == SEMsgType.SEMSG_OK)

                if ready_to_run:
                    ack_msg = segrind_run.send_execute_cmd()
                    if ack_msg and ack_msg.msgtype != SEMsgType.SEMSG_ACK:
                        result = segrind_run.read_response()

                if result is None:
                    logger.debug("Fuzzing result is None for {}".format(run_name))
                elif result.msgtype == SEMsgType.SEMSG_OK:
                    try:
                        if not using_existing_iovec:
                            logger.debug("Reading in IOVec from {}".format(segrind_run.valgrind_pid))
                            io_vec = IOVec(result.data)
                            logger.info("{} created {}".format(run_name, str(io_vec)))
                            io_vec_contents = io.StringIO()
                            io_vec.pretty_print(out=io_vec_contents)
                            logger.debug(io_vec_contents.getvalue())
                            io_vec_list.append(io_vec)
                        else:
                            logger.debug('{} accepted {}'.format(run_name, str(io_vec)))
                        successful_contexts.add(io_vec)
                    except Exception as e:
                        logger.error("{} failed to add IOVec: {}".format(run_name, str(e)))
                else:
                    if using_existing_iovec:
                        logger.debug("{} rejects {}".format(run_name, str(io_vec)))

                if len(io_vec_list) <= current_iovec_idx:
                    time.sleep(1)
            except TimeoutError as e:
                logger.debug(str(e))
                segrind_run.stop()
                continue
            except AssertionError as e:
                logger.debug(str(e))
                segrind_run.stop()
                continue
            except KeyboardInterrupt:
                logger.debug("{} received KeyboardInterrupt".format(run_name))
                segrind_run.stop()
                continue
    except Exception as e:
        logger.error("Error for {}: {}".format(run_name, e))
    finally:
        logger.info("Finished {}".format(run_name))
        segrind_run.stop()
        if os.path.exists(pipe_in):
            os.unlink(pipe_in)
        if os.path.exists(pipe_out):
            os.unlink(pipe_out)
        del segrind_run
        return FuzzRunResult(fuzz_desc.func_desc, successful_contexts, coverages)


def fuzz_functions(func_descs, valgrind_loc, watchdog, duration,
                   work_dir=os.path.abspath(os.path.join(os.curdir, "_work"))):
    fuzz_runs = list()
    unclassified = set()

    if not os.path.exists(work_dir):
        os.makedirs(work_dir, exist_ok=True)

    for func_desc in func_descs:
        fuzz_runs.append(FuzzRunDesc(func_desc, valgrind_loc, work_dir, watchdog))

    with mp.Manager() as manager:
        generated_iovecs = manager.list()
        iovec_coverage = manager.dict()

        processes = list()
        for func_desc in func_descs:
            processes.append(
                mp.Process(target=fuzz_one_function, args=(func_desc, generated_iovecs, iovec_coverage, duration,)))

        for p in processes:
            p.start()

        time_left = duration
        while time_left > 0:
            if not any(p.is_alive() for p in processes):
                break
            time.sleep(1)
            time_left -= 1

        for p in processes:
            if p.is_alive():
                p.terminate()

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
    # parser.add_argument("-threads", help="Number of threads to use", type=int, default=mp.cpu_count())
    parser.add_argument("-map", help="/path/to/context/map", default="hash.map")
    parser.add_argument('-o', '--out', help="/path/to/output/function/descriptions", default="out.desc")
    parser.add_argument('-c', '--cov', help="/path/to/coverage/output", default='cov.map')
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

    hash_file = os.path.abspath(results.map)
    if not os.path.exists(os.path.dirname(hash_file)):
        os.makedirs(os.path.dirname(hash_file), exist_ok=True)

    map_file = os.path.abspath(results.out)
    if not os.path.exists(os.path.dirname(map_file)):
        os.makedirs(os.path.dirname(map_file), exist_ok=True)

    args = list()
    logger.debug("Building fuzz target list")
    func_count = len(location_map)
    for location, func_desc in location_map.items():
        args.append(func_desc)
    logger.debug("done")
    logger.info("Fuzzing {} targets".format(len(args)))

    if len(args) > 0:
        (fuzz_run_results, unclassified) = fuzz_functions(args, valgrind_loc=valgrind_loc, watchdog=results.timeout,
                                                          duration=results.duration)

        logger.info("{} has {} functions".format(results.bin, func_count))
        logger.info("Fuzzable functions: {}".format(len(fuzz_run_results)))
        if len(unclassified) > 0:
            logger.info("Unclassified functions:")
            for func_desc in unclassified:
                logger.info(func_desc.name)

        context_hashes = dict()
        desc_map = dict()
        # coverage_map = dict()

        # total_instructions = dict()
        # executed_instructions = set()

        for func_desc, fuzz_run_result in fuzz_run_results.items():
            # coverage_map[func_desc] = list()
            for hash_sum, io_vec in fuzz_run_result.io_vecs.items():
                context_hashes[hash_sum] = io_vec
                # for coverage_tuple in fuzz_run_result.coverages[hash(io_vec)]:
                #     individual_executed = list()
                #     for addr in coverage_tuple[0]:
                #         executed_instructions.add(addr)
                #         individual_executed.append(addr)
                #     individual_executed.sort()
                #     total_instructions[coverage_tuple[0][0]] = coverage_tuple[1]
                #     coverage_map[func_desc].append((individual_executed, coverage_tuple[1]))

                if hash_sum not in desc_map:
                    desc_map[hash_sum] = set()
                desc_map[hash_sum].add(func_desc)

        # whole_coverage = dict()
        # full_count = dict()
        # percent_covered = dict()
        # for func_desc, coverages in coverage_map.items():
        #     for (instructions, n_instructions) in coverages:
        #         start = instructions[0]
        #         if start not in whole_coverage:
        #             whole_coverage[start] = set()
        #         if start not in full_count:
        #             full_count[start] = n_instructions
        #         for i in instructions:
        #             whole_coverage[start].add(i)

        # total_executed = 0
        # total_reachable = 0
        # percentages = list()
        # for start, covered_instructions in whole_coverage.items():
        #     print("{}: {}/{} = {}".format(hex(start), len(covered_instructions), full_count[start],
        #                                   len(covered_instructions) / full_count[start]))
        #     percent_covered[start] = len(covered_instructions) / full_count[start]
        #     percentages.append(len(covered_instructions) / full_count[start])
        #     total_executed += len(covered_instructions)
        #     total_reachable += full_count[start]
        #
        # print("Mean function coverage: {}".format(statistics.mean(percentages)))
        # print("Total coverage: {} / {} = {}".format(total_executed, total_reachable, total_executed / total_reachable))

        # with open(results.cov, "wb") as cov_out:
        #     pickle.dump(coverage_map, cov_out)
        #
        # with open(results.cov + ".pct", 'wb') as pct_out:
        #     pickle.dump(percent_covered, pct_out)
        #
        # with open(results.cov + ".whole", 'wb') as whole_out:
        #     pickle.dump(whole_coverage, whole_out)

        with open(hash_file, "wb") as hashes_out:
            pickle.dump(context_hashes, hashes_out)

        with open(map_file, "wb") as map_out:
            pickle.dump(desc_map, map_out)

    else:
        logger.fatal("Could not find any functions to fuzz")


if __name__ == "__main__":
    main()
