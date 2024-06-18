# from output_gen_lib import analyze_program
from output_gen_lib import analyze_program, uncompress_analyze
import pandas
import os
COMPRESSED_DIR = "../generated/generated_compressed"

cs = pandas.read_csv("../outputs.csv")
filenames = set(cs.pop("filename"))

csv = open("../outputs.csv", "a")

ls = os.listdir(COMPRESSED_DIR)
for file in ls:

    file_path = os.path.join(COMPRESSED_DIR, file)
    filename = file[:-4]
    if filename in filenames:
        continue

# analyze_program("generated/generated_test/vuln2")
    total_vulns = uncompress_analyze(file_path)
    to_write = filename + "," + total_vulns
    commas_to_add = 15 - to_write.count(",")
    csv.write(to_write + ","*commas_to_add + "\n")
# analyze_program("generated/generated_test/a.out")

csv.close()