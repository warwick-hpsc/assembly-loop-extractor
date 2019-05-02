import os

script_dirpath = os.path.dirname(os.path.realpath(__file__))
import imp
imp.load_source('assembly_analysis', os.path.join(script_dirpath, "assembly_analysis.py"))
from assembly_analysis import *

obj_filepath = os.path.join(script_dirpath, "loops.o")
loop_name = "compute_flux_edge"

d = {}
d["compiler"] = "gnu"
d["SIMD len"] = 1

## If source function contains multiple loop candidates, but 
## just one is of particular interest, then knowing the number of 
## instructions executed per iteration (eg measure with PAPI) helps 
## to pinpoint the correct loop:
# ins_per_iter = 284
ins_per_iter = -1
loop, asm_loop_filepath = extract_loop_kernel_from_obj(obj_filepath, d, ins_per_iter, loop_name)

loop_tally = count_loop_instructions(asm_loop_filepath, loop)
loop_tally_filepath = asm_loop_filepath + ".tally.csv"
with open(loop_tally_filepath, "w") as outfile:
  outfile.write("insn,count\n")
  for insn in loop_tally.keys():
    outfile.write("{0},{1}\n".format(insn, loop_tally[insn]))
  print("Loop tally written to: {0}".format(loop_tally_filepath))

exec_unit_tally = categorise_instructions_tally(loop_tally_filepath)
exec_unit_tally_filepath = asm_loop_filepath + ".eu_tally.csv"
with open(exec_unit_tally_filepath, "w") as outfile:
  outfile.write("eu,count\n")
  for insn in exec_unit_tally.keys():
    outfile.write("{0},{1}\n".format(insn, exec_unit_tally[insn]))
  print("Exec unit tally written to: {0}".format(exec_unit_tally_filepath))
