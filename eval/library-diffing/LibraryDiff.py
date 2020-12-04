import re
import subprocess
import os


def get_git_diffs(version1, version2):
    add_regex_str = "(\d*) insertion"
    del_regex_str = "(\d*) deletion"
    stat_regex_str = "(\S+)\s+|"

    add_regex = re.compile(add_regex_str)
    del_regex = re.compile(del_regex_str)
    stat_regex = re.compile(stat_regex_str)

    total_adds = 0
    total_dels = 0

    cmd = ['git', 'diff', version1, version2, '--stat']
    diff_result = subprocess.run(cmd, stdout=subprocess.PIPE)

    for line in diff_result.stdout.decode('utf-8'):
        stat_match = stat_regex.match(line)
        if stat_match:
            file_name = stat_match.group(1)
            _, extension = os.path.splitext(file_name)
            if extension not in ('.c', '.h'):
                continue
            stat_cmd = cmd
            stat_cmd.append('--')
            stat_cmd.append(file_name)

            file_diff = subprocess.run(stat_cmd, stdout=subprocess.PIPE)
            for diff_stat in file_diff.stdout.decode('utf-8'):
                add_match = add_regex.match(diff_stat)
                del_match = del_regex.match(diff_stat)

                if add_match:
                    total_adds += int(add_match.group(1))

                if del_match:
                    total_dels += int(del_match.group(1))

    return total_adds, total_dels
