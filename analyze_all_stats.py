import os
import csv
import shutil
import numpy as np


def process_csv_files_in_subfolder(subfolder_path):
    """
    Process all CSV files in a given subfolder:
    - ignore 'run_index' and 'alg' columns
    - compute statistics for numeric columns (mean, std, median, min, max)
    - return dict {file_name_without_ext: {field: {stat_name: value}}}
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

        stats_per_field = {}
        for field, vals in values.items():
            if len(vals) == 0:
                continue
            arr = np.array(vals, dtype=float)
            stats_per_field[field] = {
                "mean": float(np.mean(arr)),
                "std": float(np.std(arr, ddof=1)) if len(arr) > 1 else 0.0,
                "median": float(np.median(arr)),
                "min": float(np.min(arr)),
                "max": float(np.max(arr)),
            }

        base_name = file_name[:-4]  # strip ".csv"
        files_data[base_name] = stats_per_field

    return files_data


def generate_latex_stats_table(all_files_data, final_results_folder):
    """
    Generate a single LaTeX table containing statistics
    (mean, std, median, min, max) for all subfolders and files.
    First column: 'subfolder/file', then columns for each metric.
    """
    latex_filename = os.path.join(final_results_folder, "final_results_stats_table.tex")
    with open(latex_filename, 'w') as tex_file:
        tex_file.write("\\begin{table}[ht]\n\\centering\n")
        tex_file.write("\\footnotesize\n")
        tex_file.write("\\setlength{\\tabcolsep}{3pt}\n")

        # Qui puoi scegliere quali campi mostrare in tabella.
        # Presumo che i CSV abbiano almeno queste colonne:
        main_fields = [
            "time_ns",
            "time_us",
            "msg_len",
            "total_cycles",
            "total_instructions",
            "l1_cache_miss",
            "ram_usage",
        ]

        # intestazione delle colonne
        header_cols = ["File"]
        for field in main_fields:
            header_cols.extend([
                f"{field} mean",
                f"{field} std",
                f"{field} median",
                f"{field} min",
                f"{field} max",
            ])

        # costruisci specifica colonne LaTeX (1 colonna testo + resto numerico)
        num_cols = 1 + len(main_fields) * 5
        col_spec = "l" + "r" * (num_cols - 1)
        tex_file.write(f"\\begin{tabular}{{{col_spec}}}\n\\toprule\n")

        # riga header
        tex_file.write(" & ".join(header_cols) + " \\\\ \\midrule\n")

        # righe dati
        for subfolder in sorted(all_files_data.keys()):
            files_data = all_files_data[subfolder]
            for file_name in sorted(files_data.keys()):
                stats_per_field = files_data[file_name]
                full_label = f"{subfolder}/{file_name}"

                row_values = [full_label]
                for field in main_fields:
                    field_stats = stats_per_field.get(field, None)
                    if field_stats is None:
                        row_values.extend([""] * 5)
                    else:
                        row_values.append(f"{field_stats['mean']:.2f}")
                        row_values.append(f"{field_stats['std']:.2f}")
                        row_values.append(f"{field_stats['median']:.2f}")
                        row_values.append(f"{field_stats['min']:.2f}")
                        row_values.append(f"{field_stats['max']:.2f}")

                tex_file.write(" & ".join(row_values) + " \\\\ \n")

        tex_file.write("\\bottomrule\n\\end{tabular}\n")
        tex_file.write("\\caption{Summary statistics (mean, standard deviation, median, minimum, maximum) for all benchmarked algorithms and subfolders.}\n")
        tex_file.write("\\label{tab:all_stats}\n")
        tex_file.write("\\end{table}\n")


def process_results(root_folder):
    """
    Recursively walk through ALL subfolders of root_folder (e.g. 'result'),
    generate:
    - one global LaTeX table with statistics in result/final_results/
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
        generate_latex_stats_table(all_files_data, final_results_folder)
        print("LaTeX statistics table generated in 'result/final_results/final_results_stats_table.tex'.")
    else:
        print("No CSV data found to process.")


if __name__ == "__main__":
    process_results('result')
