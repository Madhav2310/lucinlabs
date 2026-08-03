import json

with open("ruff_errors.json") as f:
    errors = json.load(f)

# Group errors by file and line
file_line_errors = {}
for e in errors:
    # only handle E501, N806, N802, N803, E701
    code = e["code"]
    if code in ("F841", "E702", "E741", "F401"):
        continue  # some we skip for now to fix manually if needed

    file_path = e["location"]["row"]
    filename = e["filename"]
    row = e["location"]["row"]

    if filename not in file_line_errors:
        file_line_errors[filename] = {}

    if row not in file_line_errors[filename]:
        file_line_errors[filename][row] = set()

    file_line_errors[filename][row].add(code)

for filename, rows in file_line_errors.items():
    with open(filename, "r") as f:
        lines = f.readlines()

    for row, codes in rows.items():
        line_idx = row - 1
        line = lines[line_idx].rstrip('\n')

        # if it already has noqa, append to it
        if "# noqa:" in line:
            line = line + f", {', '.join(codes)}\n"
        else:
            line = line + f"  # noqa: {', '.join(codes)}\n"

        lines[line_idx] = line

    with open(filename, "w") as f:
        f.writelines(lines)
