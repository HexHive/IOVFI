import os
import subprocess
from concurrent import futures

from .FBLogging import logger
from .FunctionDescriptor import FunctionDescriptor
from .IOVec import IOVec
from .SEGrindRun import SEGrindRun, SEMsgType

WATCHDOG = 5.0
MAX_RETRY_COUNT = 3
MAX_ATTEMPTS = 100


class RunDesc:
    def __init__(self, func_desc, valgrind_loc, work_dir, watchdog):
        self.func_desc = func_desc
        self.valgrind_loc = os.path.abspath(valgrind_loc)
        self.work_dir = os.path.abspath(work_dir)
        self.watchdog = watchdog


class FuzzRunDesc(RunDesc):
    def __init__(self, func_desc, valgrind_loc, work_dir, watchdog, fuzz_count, attempt_count=MAX_ATTEMPTS):
        RunDesc.__init__(self, func_desc=func_desc, valgrind_loc=valgrind_loc, work_dir=work_dir, watchdog=watchdog)
        self.fuzz_count = fuzz_count
        self.attempt_count = attempt_count


class ConsolidationRunDesc(RunDesc):
    def __init__(self, func_desc, valgrind_loc, work_dir, watchdog, contexts):
        RunDesc.__init__(self, func_desc=func_desc, valgrind_loc=valgrind_loc, work_dir=work_dir, watchdog=watchdog)
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


def get_log_names(func_desc):
    run_name = "{}.{}.{}".format(os.path.basename(func_desc.binary), func_desc.name, func_desc.location)
    return run_name + ".log", run_name + ".cmd.log"


def fuzz_one_function(fuzz_desc):
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
        log_names = get_log_names(fuzz_desc.func_desc)
        log_out = os.path.join("logs", "fuzz", log_names[0])
        cmd_log = os.path.join("logs", "fuzz", log_names[1])
        # cmd_log = os.path.abspath("/dev/null")
        if not os.path.exists(os.path.dirname(log_out)):
            os.makedirs(os.path.dirname(log_out), exist_ok=True)

        logger.debug("Creating SEGrindRun for {}".format(run_name))
        segrind_run = SEGrindRun(valgrind_loc=fuzz_desc.valgrind_loc, binary_loc=binary, pipe_in=pipe_in,
                                 pipe_out=pipe_out,
                                 valgrind_log_loc=log_out, run_log_loc=cmd_log, cwd=fuzz_desc.work_dir)
        logger.debug("Done")
        fuzz_count = 0
        attempts = 0

        while fuzz_count < fuzz_desc.fuzz_count:
            attempts += 1
            if attempts > fuzz_desc.attempt_count:
                raise RuntimeError("Too many attempts for {}".format(run_name))

            try:
                if not segrind_run.is_running():
                    logger.debug("Starting SEGrindRun for {}".format(run_name))
                    segrind_run.start()
                    ack_msg = segrind_run.send_set_target_cmd(target, fuzz_desc.watchdog)
                    if ack_msg is None or ack_msg.msgtype != SEMsgType.SEMSG_ACK:
                        raise RuntimeError("Could not set target {}".format(target))

                    resp_msg = segrind_run.read_response(timeout=fuzz_desc.watchdog)
                    if resp_msg is None or resp_msg.msgtype != SEMsgType.SEMSG_OK:
                        raise RuntimeError("Could not set target {}".format(target))

                # ack_msg = segrind_run.send_reset_cmd(timeout=fuzz_desc.watchdog)
                # if ack_msg is None or ack_msg.msgtype != SEMsgType.SEMSG_ACK:
                #     continue
                #
                # resp_msg = segrind_run.read_response(timeout=fuzz_desc.watchdog)
                # if resp_msg is None or resp_msg.msgtype != SEMsgType.SEMSG_OK:
                #     continue

                ack_msg = segrind_run.send_fuzz_cmd(timeout=fuzz_desc.watchdog)
                if ack_msg is None or ack_msg.msgtype != SEMsgType.SEMSG_ACK:
                    break
                resp_msg = segrind_run.read_response(timeout=fuzz_desc.watchdog)
                if resp_msg is None or resp_msg.msgtype != SEMsgType.SEMSG_OK:
                    continue

                ack_msg = segrind_run.send_execute_cmd(timeout=fuzz_desc.watchdog)
                if ack_msg is None or ack_msg.msgtype != SEMsgType.SEMSG_ACK:
                    continue

                result = segrind_run.read_response(timeout=fuzz_desc.watchdog)
                if result is not None and result.msgtype == SEMsgType.SEMSG_OK:
                    logger.debug("Reading in IOVec")
                    io_vec = IOVec(result.data)
                    # io_vec_coverage = result.get_coverage()

                    successful_contexts.add(io_vec)
                    hash_sum = hash(io_vec)
                    # coverages[hash_sum] = io_vec_coverage
                    fuzz_count += 1
                    logger.info("{} created {} ({} of {})".format(run_name, io_vec.hexdigest(), fuzz_count,
                                                                  fuzz_desc.fuzz_count))
                elif result is not None and len(result.data.getbuffer()) > 0:
                    logger.debug("Fuzzing run failed: {}".format(result.data.getvalue()))
                elif result is None:
                    logger.debug("Fuzzing result is None")
                elif result is not None and len(result.data.getbuffer()) == 0:
                    logger.debug("Fuzzing data is zero")
                elif result.msgtype != SEMsgType.SEMSG_OK:
                    logger.debug("Pin message is not OK: %s".format(result))
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
        logger.exception("Error for {}: {}".format(run_name, e))
    finally:
        logger.info("Finished {}".format(run_name))
        segrind_run.stop()
        if os.path.exists(pipe_in):
            os.unlink(pipe_in)
        if os.path.exists(pipe_out):
            os.unlink(pipe_out)
        del segrind_run
        return FuzzRunResult(fuzz_desc.func_desc, successful_contexts, coverages)


def fuzz_functions(func_descs, valgrind_loc, num_threads, watchdog=WATCHDOG, fuzz_count=5,
                   work_dir=os.path.abspath(os.path.join(os.curdir, "_work"))):
    fuzz_runs = list()
    io_vecs_dict = dict()
    unclassified = set()

    if not os.path.exists(work_dir):
        os.makedirs(work_dir, exist_ok=True)

    for func_desc in func_descs:
        fuzz_runs.append(FuzzRunDesc(func_desc, valgrind_loc, work_dir, watchdog, fuzz_count))

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
                logger.exception(e)
                continue

    return io_vecs_dict, unclassified


def consolidate_one_function(consolidation_run_desc):
    func_desc = consolidation_run_desc.func_desc

    work_dir = os.path.join(consolidation_run_desc.work_dir, "consolidate")
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
    segrind_run = SEGrindRun(valgrind_loc=consolidation_run_desc.valgrind_loc, binary_loc=func_desc.binary,
                             pipe_in=pipe_in, pipe_out=pipe_out, valgrind_log_loc=log_loc,
                             cwd=os.path.abspath(work_dir), run_log_loc=cmd_log_loc)
    ctx_count = 0
    retry_count = 0
    idx = 0
    logger.debug("Created pin run for {}".format(run_name))
    while idx < len(consolidation_run_desc.contexts):
        iovec = consolidation_run_desc.contexts[idx]
        if retry_count > MAX_RETRY_COUNT:
            idx += 1
            retry_count = 0
            logger.error("{} failed to properly execute {}".format(run_name, iovec.hexdigest()))
            continue

        logger.info("{} testing {}".format(run_name, iovec.hexdigest()))
        try:
            if not segrind_run.is_running():
                logger.debug("Starting segrind_run for {}".format(run_name))
                segrind_run.stop()
                segrind_run.start(timeout=consolidation_run_desc.watchdog)

                ack_msg = segrind_run.send_set_target_cmd(func_desc.location, timeout=consolidation_run_desc.watchdog)

                if ack_msg is None or ack_msg.msgtype != SEMsgType.SEMSG_ACK:
                    logger.error("Set target ACK not received for {}".format(run_name))
                    break
                resp_msg = segrind_run.read_response(timeout=consolidation_run_desc.watchdog)
                if resp_msg is None or resp_msg.msgtype != SEMsgType.SEMSG_OK:
                    logger.error("Could not set target for {}".format(run_name))
                    break
                logger.debug("pin run started for {}".format(run_name))
                ctx_count = 0
            ctx_count += 1

            logger.debug("Sending reset command for {}".format(run_name))
            ack_msg = segrind_run.send_reset_cmd(timeout=consolidation_run_desc.watchdog)
            if ack_msg is None or ack_msg.msgtype != SEMsgType.SEMSG_ACK:
                segrind_run.stop()
                retry_count += 1
                logger.error("Reset ACK not received foPinMessager {}".format(run_name))
                continue
            resp_msg = segrind_run.read_response(timeout=consolidation_run_desc.watchdog)
            if resp_msg is None or resp_msg.msgtype != SEMsgType.SEMSG_OK:
                segrind_run.stop()
                retry_count += 1
                logger.error("Could not reset for {}".format(run_name))
                if resp_msg is None:
                    logger.error("{} Received no response back".format(run_name))
                else:
                    logger.error("{} Received {} message".format(run_name, resp_msg.msgtype.name))
                continue

            logger.debug("Sending set ctx command for {}".format(run_name))
            ack_msg = segrind_run.send_set_ctx_cmd(iovec, timeout=consolidation_run_desc.watchdog)
            if ack_msg is None or ack_msg.msgtype != SEMsgType.SEMSG_ACK:
                segrind_run.stop()
                retry_count += 1
                logger.error("Set Context ACK not received for {}".format(run_name))
                continue
            resp_msg = segrind_run.read_response(timeout=consolidation_run_desc.watchdog)
            if resp_msg is None or resp_msg.msgtype != SEMsgType.SEMSG_OK:
                segrind_run.stop()
                retry_count += 1
                logger.error("Could not set context for {}".format(run_name))
                continue

            logger.debug("Sending execute command for {}".format(run_name))
            ack_msg = segrind_run.send_execute_cmd(timeout=consolidation_run_desc.watchdog)
            if ack_msg is None or ack_msg.msgtype != SEMsgType.SEMSG_ACK:
                segrind_run.stop()
                retry_count += 1
                logger.error("Set Context ACK not received for {}".format(run_name))
                continue

            resp_msg = segrind_run.read_response(timeout=consolidation_run_desc.watchdog)
            if resp_msg is not None and resp_msg.msgtype == SEMsgType.SEMSG_OK:
                coverage = resp_msg.get_coverage()
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

    segrind_run.stop()
    del segrind_run
    if os.path.exists(pipe_in):
        os.unlink(pipe_in)
    if os.path.exists(pipe_out):
        os.unlink(pipe_out)
    logger.info("Finished {}".format(run_name))
    return desc_map


def consolidate_contexts(valgrind_loc, num_threads, contexts_mapping, watchdog=WATCHDOG,
                         work_dir=os.path.abspath(os.path.join(os.curdir, "_work"))):
    desc_map = dict()

    if not os.path.exists(work_dir):
        os.makedirs(work_dir, exist_ok=True)

    consolidation_runs = list()
    for func_desc, contexts in contexts_mapping.items():
        consolidation_runs.append(ConsolidationRunDesc(func_desc, valgrind_loc, work_dir, watchdog, contexts))

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


def get_functions_needing_fuzzing(func_desc_coverage, whole_coverage, threshold=0.7):
    result = list()

    for func_desc, coverage_data in func_desc_coverage.items():
        func_coverage = 0
        reachable_instructions = 0
        total_call_graph_coverage = 0
        for (instructions_executed, total_instructions) in coverage_data:
            start_addr = instructions_executed[0]
            func_coverage += len(instructions_executed)
            reachable_instructions += total_instructions
            total_call_graph_coverage += len(whole_coverage[start_addr])

        if reachable_instructions == 0:
            print("{} has 0 reachable instructions".format(func_desc.name))
            continue

        if func_coverage / reachable_instructions < threshold:
            if total_call_graph_coverage / reachable_instructions > threshold:
                print("{} has low {} coverage but {} call graph coverage".format(func_desc.name, func_coverage /
                                                                                 reachable_instructions,
                                                                                 total_call_graph_coverage / reachable_instructions))
            else:
                print("{} has low {} coverage and low {} call graph coverage".format(func_desc.name, func_coverage /
                                                                                     reachable_instructions,
                                                                                     total_call_graph_coverage / reachable_instructions))
                result.append(func_desc)

    return result


# def rank_iovecs(iovec_coverages, reverse=False):
#     instruction_counts = dict()
#     iovec_rankings = list()
#
#     for hash_sum, coverage_dict in iovec_coverages.items():
#         iovec_coverage = list()
#         invalid_count = 0
#         for func_desc, coverage_data in coverage_dict.items():
#             instr_executed = 0
#             reachable_instructions = 0
#             for (instructions, instruction_count) in coverage_data:
#                 start_addr = instructions[0]
#                 if start_addr not in instruction_counts:
#                     instruction_counts[start_addr] = instruction_count
#                 instr_executed += len(instructions)
#                 reachable_instructions += instruction_counts[start_addr]
#             if reachable_instructions == 0:
#                 print("{} has 0 reachable instructions".format(func_desc.name))
#                 invalid_count += 1
#                 continue
#
#             iovec_coverage.append(instr_executed / reachable_instructions)
#         iovec_rankings.append((hash_sum,
#                                statistics.harmonic_mean(iovec_coverage) * (len(coverage_dict) - invalid_count),
#                                len(coverage_dict)))
#
#     final_rankings = list()
#     for rank in iovec_rankings:
#         final_rankings.append((rank[0], rank[1] / len(instruction_counts), rank[2]))
#
#     return sorted(final_rankings, reverse=reverse, key=lambda ent: (ent[1], ent[2]))


# def compute_iovec_coverage(iovec_coverages):
#     iovec_ranks = rank_iovecs(iovec_coverages, reverse=True)
#
#     executed_instructions = set()
#     reachable_instruction_count = dict()
#     percent_coverages = list()
#
#     total_reachable_instructions = 0
#     for (hash_sum, rank, func_desc_count) in iovec_ranks:
#         coverage_dict = iovec_coverages[hash_sum]
#         for func_desc, coverage_data in coverage_dict.items():
#             for (instructions, instruction_count) in coverage_data:
#                 start_addr = instructions[0]
#                 if start_addr not in reachable_instruction_count:
#                     total_reachable_instructions += instruction_count
#                     reachable_instruction_count[start_addr] = instruction_count
#
#     for (hash_sum, rank, func_desc_count) in iovec_ranks:
#         coverage_dict = iovec_coverages[hash_sum]
#         for func_desc, coverage_data in coverage_dict.items():
#             for (instructions, instruction_count) in coverage_data:
#                 for instruction in instructions:
#                     executed_instructions.add(instruction)
#         percent_coverages.append(len(executed_instructions) / total_reachable_instructions)
#
#     return percent_coverages


# def rank_iovecs(iovec_coverages, reverse=False):
#     reachable_instruction_count = dict()
#     iovec_rankings = list()
#     instructions_executed = set()
#
#     working_list = copy.deepcopy(iovec_coverages)
#
#     total_reachable_instructions = 0
#     for hash_sum, coverage_dict in working_list.items():
#         for func_desc, coverage_data in coverage_dict.items():
#             for (instructions, instruction_count) in coverage_data:
#                 start_addr = instructions[0]
#                 if start_addr not in reachable_instruction_count:
#                     total_reachable_instructions += instruction_count
#                     reachable_instruction_count[start_addr] = instruction_count
#
#     latest_coverage = 0
#     while len(working_list) > 0:
#         max_coverage_increase = (-1, None, None)
#
#         for hash_sum, coverage_dict in working_list.items():
#             new_iovec_instructions = set()
#
#             for func_desc, coverage_data in coverage_dict.items():
#                 for (instructions, instruction_count) in coverage_data:
#                     for addr in instructions:
#                         if addr not in instructions_executed:
#                             new_iovec_instructions.add(addr)
#
#             current_coverage = (len(new_iovec_instructions) + len(instructions_executed)) / total_reachable_instructions
#             if current_coverage >= max_coverage_increase[0]:
#                 max_coverage_increase = (current_coverage, new_iovec_instructions, hash_sum)
#
#         for addr in max_coverage_increase[1]:
#             instructions_executed.add(addr)
#
#         iovec_rankings.append((max_coverage_increase[2], max_coverage_increase[0] - latest_coverage))
#         print(iovec_rankings[-1][1])
#         latest_coverage = max_coverage_increase[0]
#         del working_list[max_coverage_increase[2]]
#
#     if reverse:
#         iovec_rankings.reverse()
#     return iovec_rankings


# def compute_iovec_coverage(iovec_coverages):
#     iovec_ranks = rank_iovecs(iovec_coverages)
#
#     executed_instructions = set()
#     reachable_instruction_count = dict()
#     percent_coverages = list()
#
#     total_reachable_instructions = 0
#     for (hash_sum, rank) in iovec_ranks:
#         coverage_dict = iovec_coverages[hash_sum]
#         for func_desc, coverage_data in coverage_dict.items():
#             for (instructions, instruction_count) in coverage_data:
#                 start_addr = instructions[0]
#                 if start_addr not in reachable_instruction_count:
#                     total_reachable_instructions += instruction_count
#                     reachable_instruction_count[start_addr] = instruction_count
#
#     for (hash_sum, rank) in iovec_ranks:
#         coverage_dict = iovec_coverages[hash_sum]
#         for func_desc, coverage_data in coverage_dict.items():
#             for (instructions, instruction_count) in coverage_data:
#                 for instruction in instructions:
#                     executed_instructions.add(instruction)
#         percent_coverages.append(len(executed_instructions) / total_reachable_instructions)
#
#     return percent_coverages


def compute_total_reachable_instruction_count(coverages):
    reachable_instruction_count = dict()
    total_reachable = 0
    for coverage_data in coverages:
        for (instructions, instruction_count) in coverage_data:
            start_addr = instructions[0]
            if start_addr not in reachable_instruction_count:
                total_reachable += instruction_count
                reachable_instruction_count[start_addr] = instruction_count

    return total_reachable


def compute_total_executed_instruction_count(coverages):
    executed_instructions = set()
    for coverage_data in coverages:
        for (instructions, instruction_count) in coverage_data:
            for inst in instructions:
                executed_instructions.add(inst)
    return len(executed_instructions)
