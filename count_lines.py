
    # ------------------------------------------------
    # JUST TO COUNT LINES OF CODE IN THE REPO 
    # ------------------------------------------------

import subprocess

result_commits = subprocess.run(
    ['git', 'rev-list', '--all', '--count'],
    capture_output=True, text=True
)
total_commits = int(result_commits.stdout.strip())

# 2️⃣ Get line changes for all commits
result_log = subprocess.run(
    ['git', 'log', '--pretty=tformat:', '--numstat'],
    capture_output=True, text=True
)

added = 0
removed = 0

for line in result_log.stdout.splitlines():
    parts = line.split('\t')
    if len(parts) == 3:
        try:
            a = int(parts[0])
            r = int(parts[1])
            added += a
            removed += r
        except ValueError:
            # Binary files show '-' instead of numbers
            continue

net = added - removed

# 3️⃣ Print summary
print("===== GitHub-Style Repo Stats =====")
print(f"Total commits   : {total_commits}")
print(f"Lines added     : {added}")
print(f"Lines removed   : {removed}")
print(f"Net lines       : {net}")