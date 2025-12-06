import os
import csv
import json
import shutil
import numpy as np


def process_csv_files_in_subfolder(subfolder_path):
    """
    Process all CSV files in a given subfolder:
    - ignore 'run_index' and 'alg' columns
    - compute arithmetic mean for numeric columns
    - return dict {file_name_without_ext: {field: avg}}
    """
    files_data = {}

    for file_name in os.listdir(subfolder_path):
        if not file_name.endswith(".csv"):
            continue

        file_path = os.path.join(subfolder_path, file_name)

        with open(file_path, mode='r', newline='') as csv_file:
            reader = csv.DictReader(csv_file)
            if reader.fieldnames is None:
                continue  # empty or malformed file

            # numeric columns: all except known non-numeric ones
            numeric_fields = [
                f for f in reader.fieldnames
                if f not in ("run_index", "alg")
            ]

            values = {field: [] for field in numeric_fields}

            for row in reader:
                for field in numeric_fields:
                    val = row.get(field, "")
                    if val == "":
                        continue
                    try:
                        values[field].append(float(val))
                    except ValueError:
                        # skip non-convertible values gracefully
                        continue

        # skip file if no numeric data collected
        if all(len(v) == 0 for v in values.values()):
            continue

        averages = {
            field: float(np.mean(vals)) if len(vals) > 0 else None
            for field, vals in values.items()
        }

        base_name = file_name[:-4]  # strip ".csv"
        files_data[base_name] = averages

    return files_data


def write_per_subfolder_json(all_files_data, final_results_folder):
    """
    For each subfolder in all_files_data, write one JSON file in final_results/.
    JSON name is based on relative path, with path separators replaced by '_'.
    Keys (file names) are sorted alphabetically via sort_keys=True.
    """
    for rel_path, files_data in all_files_data.items():
        if not files_data:
            continue

        # example: rel_path = "kem/mlkem512" -> "kem_mlkem512.json"
        json_name = rel_path.replace(os.sep, "_") + ".json"
        json_path = os.path.join(final_results_folder, json_name)

        # sort by algorithm/file name in JSON
        with open(json_path, "w") as jf:
            json.dump(files_data, jf, indent=4, sort_keys=True)


def generate_latex_table(all_files_data, final_results_folder):
    """
    Generate a single LaTeX table containing averaged metrics
    for all subfolders and files, ordered alphabetically.
    First column: "subfolder/file".
    """
    latex_filename = os.path.join(final_results_folder, "final_results_table.tex")
    with open(latex_filename, 'w') as tex_file:
        tex_file.write("\\begin{table}[ht]\n\\centering\n")
        tex_file.write("\\begin{tabular}{|l|l|l|l|l|l|l|l|}\n\\hline\n")
        tex_file.write(
            "File & Time (ns) & Time (us) & Msg Len & Total Cycles & "
            "Total Instructions & L1 Cache Miss & RAM Usage \\\\ \\hline\n"
        )

        # iterate subfolders and files in alphabetical order
        for subfolder in sorted(all_files_data.keys()):
            files_data = all_files_data[subfolder]
            for file_name in sorted(files_data.keys()):
                file_data = files_data[file_name]
                full_label = f"{subfolder}/{file_name}"
                tex_file.write(
                    f"{full_label} & "
                    f"{file_data.get('time_ns', '')} & "
                    f"{file_data.get('time_us', '')} & "
                    f"{file_data.get('msg_len', '')} & "
                    f"{file_data.get('total_cycles', '')} & "
                    f"{file_data.get('total_instructions', '')} & "
                    f"{file_data.get('l1_cache_miss', '')} & "
                    f"{file_data.get('ram_usage', '')} \\\\ \n"
                )

        tex_file.write("\\hline\n\\end{tabular}\n")
        tex_file.write("\\caption{Average benchmark results for all algorithms and subfolders.}\n")
        tex_file.write("\\end{table}\n")


def process_results(root_folder):
    """
    Recursively walk through ALL subfolders of root_folder (e.g. 'result'),
    generate:
    - one JSON per subfolder with CSVs in result/final_results/
    - one global LaTeX table in result/final_results/
    """
    final_results_folder = os.path.join(root_folder, 'final_results')

    # 1) Remove existing final_results folder (if any)
    if os.path.exists(final_results_folder):
        shutil.rmtree(final_results_folder)

    os.makedirs(final_results_folder, exist_ok=True)

    all_files_data = {}

    # 2) Recursive walk through result/
    for dirpath, dirnames, filenames in os.walk(root_folder):
        base = os.path.basename(dirpath)

        # skip the final_results folder itself
        if base == "final_results":
            # do not descend into final_results
            dirnames[:] = []
            continue

        # don't process the root folder itself
        if os.path.abspath(dirpath) == os.path.abspath(root_folder):
            continue

        # check if this dir actually has CSVs
        has_csv = any(fname.endswith(".csv") for fname in filenames)
        if not has_csv:
            continue

        # process this subfolder
        files_data = process_csv_files_in_subfolder(dirpath)
        if files_data:
            # use relative path from root_folder as key (handles nested folders incl. kem/*)
            rel_path = os.path.relpath(dirpath, root_folder)
            all_files_data[rel_path] = files_data

    if all_files_data:
        # write per-subfolder JSON and global LaTeX
        write_per_subfolder_json(all_files_data, final_results_folder)
        generate_latex_table(all_files_data, final_results_folder)
        print("JSON data and LaTeX file generated in 'result/final_results'.")
    else:
        print("No CSV data found to process.")


if __name__ == "__main__":
    process_results('result')
