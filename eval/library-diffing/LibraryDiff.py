import re
import subprocess
import os


def get_git_diffs(version1, version2):
    stat_regex_str = "(\d*)\s+(\d*)\s+\S+"
    stat_regex = re.compile(stat_regex_str)

    total_adds = 0
    total_dels = 0

    cmd = ['git', 'diff', version1, version2, '--numstat']
    print("Running {} in {}".format(" ".join(cmd), os.getcwd()))
    diff_result = subprocess.run(cmd, stdout=subprocess.PIPE,
                                 encoding='UTF-8').stdout

    for line in diff_result.readline():
        line = line.strip()
        stat_match = stat_regex.match(line)
        if stat_match:
            file_name = stat_match.group(3)
            _, extension = os.splitext(file_name)
            if extension in (".c", ".h"):
                total_adds += int(stat_match.group(1))
                total_dels += int(stat_match.group(2))

    return total_adds, total_dels
