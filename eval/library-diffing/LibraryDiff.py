import re
import subprocess
import sys


def get_git_diffs(version1, version2):
    add_regex_str = "(\d*) insertion"
    del_regex_str = "(\d*) deletion"

    add_regex = re.compile(add_regex_str)
    del_regex = re.compile(del_regex_str)

    total_adds = 0
    total_dels = 0

    cmd = ['find', '.', '-name', '\"*.[c,h]\"', '-exec', 'git', 'diff', version1, version2, '--stat', '--', '{}', '\\;']
    print('Running: ', cmd)
    diff_result = subprocess.run(cmd,
                                 stdout=subprocess.PIPE)

    for line in diff_result.stdout.decode('utf-8'):
        add_match = add_regex.match(line)
        del_match = del_regex.match(line)

        if add_match:
            total_adds += int(add_match.group(1))

        if del_match:
            total_dels += int(del_match.group(1))

    return total_adds, total_dels
