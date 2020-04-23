import os
import subprocess

from .FunctionDescriptor import FunctionDescriptor


class RunDesc:
    def __init__(self, func_desc, valgrind_loc, work_dir, watchdog):
        self.func_desc = func_desc
        self.valgrind_loc = os.path.abspath(valgrind_loc)
        self.work_dir = os.path.abspath(work_dir)
        self.watchdog = watchdog


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


# def get_functions_needing_fuzzing(func_desc_coverage, whole_coverage, threshold=0.7):
#     result = list()
#
#     for func_desc, coverage_data in func_desc_coverage.items():
#         func_coverage = 0
#         reachable_instructions = 0
#         total_call_graph_coverage = 0
#         for (instructions_executed, total_instructions) in coverage_data:
#             start_addr = instructions_executed[0]
#             func_coverage += len(instructions_executed)
#             reachable_instructions += total_instructions
#             total_call_graph_coverage += len(whole_coverage[start_addr])
#
#         if reachable_instructions == 0:
#             print("{} has 0 reachable instructions".format(func_desc.name))
#             continue
#
#         if func_coverage / reachable_instructions < threshold:
#             if total_call_graph_coverage / reachable_instructions > threshold:
#                 print("{} has low {} coverage but {} call graph coverage".format(func_desc.name, func_coverage /
#                                                                                  reachable_instructions,
#                                                                                  total_call_graph_coverage / reachable_instructions))
#             else:
#                 print("{} has low {} coverage and low {} call graph coverage".format(func_desc.name, func_coverage /
#                                                                                      reachable_instructions,
#                                                                                      total_call_graph_coverage / reachable_instructions))
#                 result.append(func_desc)
#
#     return result


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
