import os
import re
from sets import Set
import copy
import pandas as pd
import sys

from pprint import pprint

class Loop(object):
  def __init__(self, start, end, isroot=False):
    self.start = start
    self.end = end
    self.total_length = end - start + 1
    self.real_length  = end - start + 1
    self.inner_loops = []
    self.isroot = isroot

    self.ctr_step = -1

  def print_loop(self, indent):
    s = ""
    if self.isroot:
      s = "ROOT"
    else:
      # l = self.real_length
      l = self.total_length
      s = " "*indent + "{0} -> {1} [{2}]".format(self.start, self.end, l)
      # s = " "*indent + "{0} -> {1}".format(self.start, self.end)
    for il in self.inner_loops:
      s += "\n" + il.print_loop(indent+1)
    return s

  def __str__(self):
    return self.print_loop(0)

  def __hash__(self):
    return self.end

  def __eq__(self, other):
    return (isinstance(other, Loop) and self.start == other.start and self.end == other.end)

def clean_asm_file(asm_filepath, func_name=""):
  asm_clean_filepath = asm_filepath + ".clean"

  cmnt_line_rgx = re.compile("^ *#")
  empty_line_rgx = re.compile("^[ \t]*$")
  jump_ins_rgx = re.compile("^[ \t]*j")
  jump_label_intel_rgx = re.compile("^\.\.B[0-9]\.[0-9]+:")
  jump_label_gnu_rgx = re.compile("^\.L[0-9]+:")
  jump_label_obj_rgx = re.compile("^[0-9a-z]+$")
  noise_rgx = re.compile("^[\.]+[a-zA-Z]")

  if func_name != "":
    func_name_rgx = re.compile("^.*{0}[^_].*$".format(func_name))

  with open(asm_clean_filepath, "w") as asm_out:
    num_lines_written = 0
    with open(asm_filepath, "r") as asm:
      ## Check whether to begin parsing:
      if func_name != "":
        parse = False
      else:
        parse = True

      i=0
      prev_line = ""
      for line in asm:
        i += 1

        ## Check whether to stop parsing:
        if parse and "<" in line:
          ## Use '<' character as an indicator for function name presence
          if func_name != "" and not func_name_rgx.match(line):
            # print("Have stopped parsing at line {0}".format(i))
            parse = False
            break
        elif parse and "Disassembly" in line:
          if func_name != "" and not func_name in line:
            parse = False
            break

        line = line.replace('\t', ' ')
        line = re.sub(r" +", " ", line)
        line = re.sub(r"^ *", "", line)
        line = re.sub(r"#.*", "", line)

        if not parse:
          if func_name != "" and func_name_rgx.match(line):
            parse = True
          else:
            prev_line = line
            continue

        if cmnt_line_rgx.match(line):
          continue
        elif empty_line_rgx.match(line):
          continue
        elif noise_rgx.match(line) and not (jump_label_intel_rgx.match(line) or jump_label_gnu_rgx.match(line)):
          continue
        elif "(bad)" in line:
          continue
        elif "Disassembly" in line:
          continue

        if prev_line != "":
          asm_out.write(prev_line)
          num_lines_written += 1
          prev_line = ""
        asm_out.write(line)
        num_lines_written += 1

    if num_lines_written == 0:
      print("ERROR: Could not find assembly code for function '{0}'".format(func_name))
      sys.exit(-1)

  return asm_clean_filepath


class AssemblyOperation(object):
  def __init__(self, operation, label, line_num, idx):
    self.label = label
    self.line_num = line_num
    self.idx = idx
    self.operation = operation

    operation = re.sub(r" *$", "", operation)
    operation_pieces = operation.split(' ')
    self.instruction = operation_pieces[0]
    if len(operation_pieces) == 1:
      self.operands = None
    else:
      operands = ' '.join(operation_pieces[1:])
      operands = list(operands)
      bracket_depth=0
      for i in range(len(operands)):
        if operands[i] == "(":
          bracket_depth+=1
        elif operands[i] == ")":
          bracket_depth-=1
        if (operands[i]==",") and (bracket_depth==0):
          operands[i] = " "
      operands = ''.join(operands)
      self.operands = operands.split(' ')
      for i in range(len(self.operands)-1, -1, -1):
        try:
          if list(self.operands[i])[0] == "<":
            del self.operands[i]
        except:
          print("ERROR:")
          pprint(instruction)
          pprint(self.operands)
          sys.exit(-1)

  def __str__(self):
    s = "  Instruction: '" + self.instruction + "'"
    s += "\n"
    s += "  Index: '" + str(self.idx) + "'"
    s += "\n"
    if hasattr(self, "jump_target_idx"):
      s += "  Jump to: " + str(self.jump_target_idx)
      s += "\n"
    s += "  Label: '" + self.label + "'"
    s += "\n"
    s += "  Line num: '" + str(self.line_num) + "'"
    s += "\n"
    if self.operands != None:
      s += "  Operands: [ " + ' , '.join(self.operands) + " ]"
      s += "\n"
    return(s)

  def __hash__(self):
    return self.idx

  def __eq__(self, other):
    return (isinstance(other, AssemblyOperation) and self.idx == other.idx)

  def __ne__(self, other):
    return not self.__eq__(other)


class AssemblyObject(object):
  def __init__(self, asm_filepath, func_name):
    self.asm_filepath = asm_filepath

    self.asm_clean_filepath = clean_asm_file(asm_filepath, func_name)

    self.asm_clean_numLines = 0
    for line in open(self.asm_clean_filepath).xreadlines():
      self.asm_clean_numLines += 1

    self.parse_asm()
    self.identify_jumps()

  def parse_asm(self):
    self.operations = []
    self.labels = []
    self.label_to_ins = {}
    self.label_to_idx = {}
    with open(self.asm_clean_filepath) as assembly:
      # print("Parsing instructions in: " + self.asm_clean_filepath)
      line_num = 0
      idx = -1
      for line in assembly:
        line_num += 1
        line = line.replace('\n', '')

        current_label = line.split(':')[0]
        line = ':'.join(line.split(':')[1:])
        line = re.sub(r"^[ \t]*", "", line)
        idx += 1
        operation = AssemblyOperation(line, current_label, line_num, idx)
        self.operations.append(operation)

        self.labels.append(current_label)
        self.label_to_ins[current_label] = line
        self.label_to_idx[current_label] = idx

  def identify_jumps(self):
    # print("Identifying jumps in: " + self.asm_clean_filepath)
    self.jump_ops = Set()
    self.jump_op_indices = Set()
    self.jump_target_labels = Set()
    self.jump_target_label_indices = Set()
    for i in range(len(self.operations)):
      op = self.operations[i]
      if op.instruction[0] == "j":
        if ((i+1)*2) == self.asm_clean_numLines:
          ## Ignore jump on final line.
          continue

        jump_target_label = op.operands[0]
        if not jump_target_label in self.label_to_idx.keys():
          if jump_target_label.startswith("0x"):
            jump_target_label2 = re.sub(r"^0x", "", jump_target_label)
            if jump_target_label2 in self.label_to_idx.keys():
              ## Jump instructions have target "0x...", but lines labels lack the "0x". 
              self.label_to_idx[jump_target_label] = self.label_to_idx[jump_target_label2]

        if not jump_target_label in self.label_to_idx.keys():
          # print("ERROR: Unknown jump label {0} on line {1}".format(jump_target_label, op.line_num))
          # sys.exit(-1)
          print(" - notice: Ignoring jump on line {1} to unknown label {0}".format(jump_target_label, op.line_num))
          continue

        self.jump_target_labels.add(jump_target_label)
        jump_target_idx = self.label_to_idx[jump_target_label]
        self.jump_target_label_indices.add(jump_target_idx)

        op_copy = copy.deepcopy(op)
        op_copy.jump_target_idx = jump_target_idx
        self.jump_ops.add(op_copy)
        self.jump_op_indices.add(i)

  def write_out_asm_simple(self):
    self.assembly_simple_filepath = self.asm_filepath + ".simple"
    with open(self.assembly_simple_filepath, "w") as out_file:
      for op in self.operations:
        out_file.write(op.instruction)
        if op.operands != None and len(op.operands) > 0:
          if op.operands[0] in self.jump_target_labels:
            out_file.write(" LINE#" + str(self.label_to_idx[op.operands[0]]+1))
          else:
            for operand in op.operands:
              out_file.write(" " + operand)

        out_file.write("\n")

def obj_to_asm(obj_filepath):
  if not os.path.isfile(obj_filepath):
    print("ERROR: Cannot find file '" + obj_filepath + "'")
    sys.exit(-1)

  ## Extract raw assembly:
  asm_filepath = obj_filepath + ".asm"
  # objdump_command = "objdump -D --no-show-raw-insn {0}".format(obj_filepath)
  objdump_command = "objdump -d --no-show-raw-insn {0}".format(obj_filepath)
  objdump_command += ' | sed "s/^Disassembly of section/ fnc: Disassembly/g"'
  objdump_command += ' | sed "s/:$//g"'
  objdump_command += ' | grep "^ "'
  objdump_command += ' | grep ":"'
  objdump_command += ' | sed "s/^[ \t]*//g"'
  objdump_command += " > {0}".format(asm_filepath)
  # print(objdump_command)
  os.system(objdump_command)
  if not os.path.isfile(asm_filepath):
    print("ERROR: objdump failed")
    sys.exit(-1)

  return asm_filepath

def extract_loop_kernel_from_obj(obj_filepath, job_profile, 
                                 expected_ins_per_iter=0.0, 
                                 func_name="", 
                                 avx512cd_required=False, 
                                 num_conflicts_per_iteration = 1):
  if not os.path.isfile(obj_filepath):
    print("ERROR: Cannot find file '" + obj_filepath + "'")
    sys.exit(-1)

  # print("Analysing '{0}'".format(obj_filepath))

  asm_filepath = obj_to_asm(obj_filepath)

  asm_obj = AssemblyObject(asm_filepath, func_name)

  ## Extract labels:
  operations = asm_obj.operations
  labels = asm_obj.labels
  label_to_ins = asm_obj.label_to_ins
  label_to_idx = asm_obj.label_to_idx

  avx512_used = False
  for op in operations:
    if "kortest" in op.instruction:
      avx512_used = True
      break

  ## Extract jumps:
  jump_ops = asm_obj.jump_ops
  jump_op_indices = asm_obj.jump_op_indices
  jump_target_labels = asm_obj.jump_target_labels
  jump_target_label_indices = asm_obj.jump_target_label_indices

  ## Write another version of assembly, removing unused line labels:
  asm_obj.write_out_asm_simple()

  ## Identify AVX-512 masked serial remainder loops:
  avx512_conflict_loops = []
  if avx512_used:
    ## Find and discard jumps used by AVX-512-CD masked serial loops:
    for jump_op in copy.deepcopy(jump_ops):
      if not jump_op in jump_ops:
        ## 'jump_op' was removed from 'jump_ops' during loop
        continue

      if jump_op.jump_target_idx > jump_op.idx:
        ## Not interested in forward jumps.
        continue

      if (jump_op.idx - jump_op.jump_target_idx) > 20:
        ## Serial remainder loops should be small
        continue

      serial_remainder_loop_found = False

      ## Search backwards for another jump that closely bypasses 'jump_op'. 
      ## To be the bypass jump, 2 conditions must be met:
      ## 1 - Source position within 10 instructions before jump_op's target
      ## 2 - Target position within 5 instructions of jump_op's position
      forward_bypass_jump_found = False
      forward_bypass_jump = None
      threshold_pre=10
      threshold_post=5
      for i in range(jump_op.idx-1, jump_op.jump_target_idx-10, -1):
        if i in jump_op_indices:
          jump_op2 = [j for j in jump_ops if j.idx==i][0]

          if (jump_op.jump_target_idx > jump_op2.idx) and \
             (jump_op.jump_target_idx - jump_op2.idx < threshold_pre) and \
             (jump_op2.jump_target_idx > jump_op.idx) and \
             (jump_op2.jump_target_idx - jump_op.idx < threshold_post):
             ## This is the forward bypass jump: 
             forward_bypass_jump_found = True
             forward_bypass_jump = jump_op2
             break
          else:
            ## Any other type of jump immediately rules out 'jump_op' as being 
            ## a serial remainder loop
            break

      if not forward_bypass_jump_found:
        continue

      ## Now to confirm that serial remainder loop has been found, look for 
      ## the kortest instruction that should closely precede the jump back:
      kortest_found = False
      for i in range(forward_bypass_jump.jump_target_idx-1, forward_bypass_jump.jump_target_idx-5, -1):
        op = operations[i]
        if "kortest" in op.instruction:
          kortest_found = True
          break

      serial_remainder_loop_found = forward_bypass_jump_found and kortest_found

      if serial_remainder_loop_found:
        jump_ops.remove(jump_op)
        jump_op_indices.remove(jump_op.idx)
        jump_target_label_indices.remove(jump_op.jump_target_idx)
        ## Next, find the bypass jump that surrounds loop:
        found_bypass = False
        for jump_op2 in jump_ops:
          if ((jump_op2.jump_target_idx-jump_op.idx) < 5) and (jump_op2.jump_target_idx > jump_op.idx):
            ## Found it
            found_bypass = True
            jump_ops.remove(jump_op2)
            jump_op_indices.remove(jump_op2.idx)
            jump_target_label_indices.remove(jump_op2.jump_target_idx)
            break
        if not found_bypass:
          print("ERROR: Did not find bypass jump for AVX-512-CD jump:")
          print(jump_op)
          sys.exit(-1)

        avx512_conflict_loops.append(jump_op)

  n = len(avx512_conflict_loops)
  if n==0 and avx512_used and avx512cd_required:
    print("AVX512 used and conflict detection required but no conflict detection loops found.")
    sys.exit(-1)
  if n!=0 and avx512_used and not avx512cd_required:
    print("AVX512 used nd conflict detection not required but conflict detection loops were found.")
    sys.exit(-1)
  if n%num_conflicts_per_iteration != 0:
    print("Number of detected AVX512 conflict loops not a multiple of {0}: {1}".format(num_conflicts_per_iteration, n))
    sys.exit(-1)
  if avx512_used:
    print("{0}x avx512_conflict_loops".format(n))

  jump_ops = list(jump_ops)
  jump_ops.sort(key=lambda j: j.idx)

  loop_len_threshold = 5

  # ## added for GCC compatibility?
  # ## New method for setting loop length threshold: 50% of biggest jump:
  # jump_distances = [abs(j.idx - j.jump_target_idx) for j in jump_ops]
  # jump_distances.sort(reverse=True)
  # loop_len_threshold = jump_distances[0] / 2;
  # print("loop_len_threshold = {0}".format(loop_len_threshold))

  ## Identify backward jumps that follow a compare
  loop_jump_ops = Set()
  for jump_op in jump_ops:
    jump_idx = jump_op.idx
    jump_target_idx = label_to_idx[jump_op.operands[0]]
    if jump_target_idx < jump_idx:
      ## Seach backwards from 'jump_op' for a compare:
      for i in range(jump_idx-1, jump_target_idx-1, -1):
        if i in jump_op_indices:
          ## Another jump found before compare, so discard:
          break
        op = operations[i]
        if "cmp" in op.instruction:
          # if (jump_idx-jump_target_idx+1) > loop_len_threshold:
          #   loop_jump_ops.add(jump_op)
          ## Update: apply threshold at a later stage.
          loop_jump_ops.add(jump_op)
          break

  loop_jump_ops = list(loop_jump_ops)
  loop_jump_ops.sort(key=lambda j: (j.idx+j.jump_target_idx)/2)

  # print("{0} backward jumps found".format(len(loop_jump_ops)))
  # for l in loop_jump_ops:
  #   print(l)
  # quit()

  # ## Identify forward jumps (added for GCC compatibility?):
  # forward_jumps = []
  # for jump_op in jump_ops:
  #   if jump_op.idx < label_to_idx[jump_op.operands[0]]:
  #     forward_jumps.append(jump_op)
  # if len(forward_jumps) > 0:
  #   print("{0} forward_jumps".format(len(forward_jumps)))
  #   print("forward_jumps:")
  #   for o in forward_jumps:
  #     # print(o)
  #     # print("  Jumps to line idx {0}".format(o.jump_target_idx))
  #     # print("  Loop length is {0} instructions.".format(o.idx - o.jump_target_idx + 1))
  #     print("  {0} -> {1} ({2} instructions)".format(o.idx, o.jump_target_idx, o.jump_target_idx-o.idx+1))
  #     # print("")
  # quit()

  ## Next identify unbroken instruction sequences within these loops:
  jump_target_label_indices_sorted = list(jump_target_label_indices)
  jump_target_label_indices_sorted.sort()
  loops = Set()
  for loop_jump_op in loop_jump_ops:
    # print("")
    # print("Processing loop {0} -> {1}.".format(loop_jump_op.jump_target_idx, loop_jump_op.idx))
    # print(loop_jump_op.__str__())

    loop_start_idx = loop_jump_op.jump_target_idx
    loop_end_idx = loop_jump_op.idx

    jump_ops_within_loop = [j for j in jump_ops if (j.idx > loop_start_idx and j.idx < loop_end_idx and j.jump_target_idx > loop_start_idx and j.jump_target_idx < loop_end_idx)]
    # if len(jump_ops_within_loop) > 0:
    #   print("Jump ops within loop:")
    #   for j in jump_ops_within_loop:
    #     print(j)

    ## I notice that with AVX-512 there are many tiny forward jumps that bypass division instructions.
    ## Discard them:
    jump_ops_within_loop_pruned = []
    length_threshold = 3
    for j in jump_ops_within_loop:
      discard_jump = False
      if (j.jump_target_idx > j.idx) and (j.jump_target_idx - j.idx <= length_threshold):
        jump_contains_div = False
        for i in range(j.idx+1, j.jump_target_idx):
          if "div" in operations[i].instruction:
            jump_contains_div = True
            break
        if jump_contains_div:
          discard_jump = True
      if not discard_jump:
        jump_ops_within_loop_pruned.append(j)
    jump_ops_within_loop = jump_ops_within_loop_pruned

    # interruption_indices = [j.idx for j in jump_ops_within_loop] + [j.jump_target_idx for j in jump_ops_within_loop]
    interruption_indices = Set()

    # exit_points = [j.idx for j in jump_ops if (j.idx > loop_start_idx and j.idx < loop_end_idx)]
    # for i in exit_points:
    #   interruption_indices.add(i+1)

    # entry_points = [j.jump_target_idx for j in jump_ops if (j.jump_target_idx >= loop_start_idx and j.jump_target_idx <= loop_end_idx)]
    # entry_points = [j.jump_target_idx for j in jump_ops if (j.idx > loop_start_idx and j.idx < loop_end_idx and j.jump_target_idx > loop_start_idx and j.jump_target_idx < loop_end_idx)]

    ## Find forward jumps that launch and land within the backward jump 'loop_jump_op', with the condition 
    ## that the quantity of instructions remaining outside of the 'forward bypass' is sufficient for a
    ## compute loop:
    entry_points = []
    # for j in jump_ops:
    #   if j.idx > loop_start_idx and j.idx < loop_end_idx and j.jump_target_idx > loop_start_idx and j.jump_target_idx < loop_end_idx:
    for j in jump_ops_within_loop:
      if j.idx > j.jump_target_idx:
        ## j is a backward jump, so target is an 'entry point'
        entry_points.append(j.jump_target_idx)
      else:
        num_insn_remaining = (j.idx - loop_start_idx + 1) + (loop_end_idx - j.jump_target_idx + 1)
        if num_insn_remaining < loop_len_threshold:
          ## This jump leaves insufficient instructions for compute, so cannot land at start of main loop.
          pass
        else:
          ## Enough instructions remain to constitute a main loop.
          entry_points.append(j.jump_target_idx)

    for i in entry_points:
      interruption_indices.add(i)

    interruption_indices = list(interruption_indices)
    interruption_indices.sort()

    # print("interruption_indices:")
    # pprint(interruption_indices)

    sequences = Set()
    if len(interruption_indices)==0:
      a = loop_start_idx
      b = loop_end_idx
      l = b-a+1
      if l > loop_len_threshold:
        sequences.add((a, b, l))
    else:
      a = loop_start_idx
      b = interruption_indices[0] - 1
      l = b-a+1
      if l > loop_len_threshold:
        sequences.add((a, b, l))
      for i in range(len(interruption_indices)-1):
        a = interruption_indices[i]
        b = interruption_indices[i+1] - 1
        l = b-a+1
        if l > loop_len_threshold:
          sequences.add((a, b, l))
      a = interruption_indices[len(interruption_indices)-1]
      b = loop_end_idx
      l = b-a+1
      if l > loop_len_threshold:
        sequences.add((a, b, l))

    for s in sequences:
      loops.add(Loop(s[0], s[1]))

  loops = list(loops)

  ## Remove any loops that are only slightly bigger than another inside of it:
  for i in range(len(loops)-1, -1, -1):
    l1 = loops[i]
    for l2 in loops:
      if l2 == l1:
        continue
      if l2.start >= l1.start and l2.end <= l1.end:
        diff = (l2.start - l1.start) + (l1.end - l2.end)
        if diff < loop_len_threshold:
          del loops[i]
          break

  loops.sort(key=lambda l: l.start)

  ## Select the loop that agrees with measurement of runtime measurement of #instructions:
  loop = None

  ## TODO: Filter out loops that do not increment loop ctr
  for i in range(len(loops)-1, -1, -1):
    l = loops[i]
    # print(" Analysing loop:")
    # print(" " + l.__str__())

    if operations[l.end].instruction[0] != "j":
      ## If this loop candidate does not end with a jump instruction, then 
      ## it probably is not the compute loop.
      del loops[i]
      continue

    ## Find the loop counter variable:
    cmp_op = None
    for j in range(l.end, -1, -1):
      op = operations[j]
      if op.instruction == "cmp":
        cmp_op = op
        break

    if cmp_op == None:
      print("ERROR: Failed to find cmp for loop: ")
      print(l)
      sys.exit(-1)

    ## Find add operation that adds a scalar to one of the cmp operands:
    ctr_name = ""
    for j in range(l.end, -1, -1):
      op = operations[j]
      if op.instruction == "inc":
        if op.operands[0] == cmp_op.operands[0]:
          ctr_name = cmp_op.operands[0]
        elif op.operands[0] == cmp_op.operands[1]:
          ctr_name = cmp_op.operands[1]
      elif op.instruction == "add" and op.operands[0][0:3] == "$0x":
        if op.operands[1] == cmp_op.operands[0]:
          ctr_name = cmp_op.operands[0]
        elif op.operands[1] == cmp_op.operands[1]:
          ctr_name = cmp_op.operands[1]

      if ctr_name != "":
        # print("  Loop ctr '{0}' found on line {1}".format(ctr_name, j))
        break

    if ctr_name == "":
      # print("ERROR: Failed to find ctr_name for loop: ")
      # print(l)
      # sys.exit(-1)
      print("WARNING: Failed to find ctr_name for loop: ")
      l.unroll_factor = 1
      print(l)
      continue

    # print("  ctr_name = {0}".format(ctr_name))

    ## Determine what value is added to the ctr on each iteration:
    ctr_step = 0
    for j in range(l.end, l.start-1, -1):
      op = operations[j]
      if op.instruction == "inc" and op.operands[0] == ctr_name:
        # ctr_step = 1
        # break
        ## Update: loop ctr can be incremented multiple times (for SIMD)
        ctr_step += 1
      elif "add" in op.instruction and op.operands[1] == ctr_name:
        # ctr_step = int(op.operands[0].replace('$',''), 0)
        # break
        ## Update: loop ctr can be incremented multiple times (for SIMD)
        if op.operands[0][0] == '$':
          ctr_step += int(op.operands[0].replace('$',''), 0)
    if ctr_step == 0:
      # print("  Failed to find loop ctr inc/add, discarding as a 'main loop' candidate:")
      del loops[i]
      continue
    else:
      if job_profile["compiler"] == "intel":
        ## Intel compiler maintains two loop counters. One is incremented and solely 
        ## used for bound check. The other is used for edge-array access.
        pass
      elif job_profile["compiler"] == "gnu":
        ## GNU compiler maintains one loop counter. Used both for bound check and edge-array access.
        # int_bytes = 4
        # double_bytes = 8
        # edge_element_size_bytes = (3*double_bytes) + (2*int_bytes)
        # if (ctr_step % edge_element_size_bytes) != 0:
        #   print("ERROR: ctr_step \% edge_element_size_bytes != 0")
        #   print("       ctr_step = {0}".format(ctr_step))
        #   print("       edge_element_size_bytes = {0}".format(edge_element_size_bytes))
        #   sys.exit(-1)
        # ctr_step /= edge_element_size_bytes
        ## The above logic is specific to MG-CFD loop, so not generically-applicable.
        pass
      else:
        print("ERROR: Do not know how compiler '{0}' implemented loop-bound-check.".format(job_profile["compiler"]))
        sys.exit(-1)

      if ctr_step < job_profile["SIMD len"]:
        ## This cannot be the main loop as it is not vectorised at requested width.
        # print("  ctr_step={0} < simd_len={1}, so cannot be main loop.".format(ctr_step, job_profile["SIMD len"]))
        del loops[i]
      else:
        l.ctr_step = ctr_step
        # print("  ctr_step = {0}".format(ctr_step))

        if ctr_step > job_profile["SIMD len"]:
          unroll_factor = ctr_step / job_profile["SIMD len"]
        else:
          unroll_factor = 1
        # print("  unroll_factor: {0}".format(unroll_factor))
        l.unroll_factor = unroll_factor

  # print("{0} loop candidates".format(len(loops)))

  if len(loops) == 0:
    print("ERROR: No 'main loop' candidates left.")
  else:
    loop = None

    feasible_loops = []
    for l in loops:
      if expected_ins_per_iter <= 0.0 or ((l.end-l.start+1) == round(expected_ins_per_iter*l.unroll_factor)):
        feasible_loops.append(l)
    if len(feasible_loops) == 1:
      loop = feasible_loops[0]
    elif len(feasible_loops) > 1:
      print("{0} loops detected".format(len(loops)))
      # print("multiple loops found that meet length requirements:")
      # for l in feasible_loops:
      #   print(l)
      # sys.exit(-1)
      # ## Meh, just pick one.
      # loop = feasible_loops[0]

    if loop == None:
      if avx512_used:
        ## Due to the masked inner loops that occur for write conflicts, it is 
        ## difficult to estimate exactly from assembly analysis of how many 
        ## instructions-per-iteration would be executed.
        if len(loops) == 1:
          ## Phew, just use that
          loop = loops[0]
        else:
          ## Exclude candidates that are too long, meaning that even if no write 
          ## conflicts occured would still exceed instructions-per-iteration:
          for l_idx in range(len(loops)-1, -1, -1):
            loop = loops[l_idx]

            num_ins_per_iter = expected_ins_per_iter*l.unroll_factor

            loop_minimum_length = loop.end - loop.start + 1
            for acl in avx512_conflict_loops:
              if acl.idx >= loop.start and acl.idx <= loop.end:
                loop_minimum_length -= (acl.idx - acl.jump_target_idx + 1)
            if loop_minimum_length > num_ins_per_iter:
              ## Even in best-case scenario (no write conflicts), this loop would 
              ## execute more instructions than measured instructions-per-iteration:
              del loops[l_idx]

          if len(loops) == 0:
            print("ERROR: No loop candidates exist after pruning those too long.")
            sys.exit(-1)
          elif len(loops) == 1:
            ## Phew, just use that
            loop = loops[0]
          else:
            # print("ERROR: {0} main loop candidates detected, unsure which to use.".format(len(loops)))
            # sys.exit(-1)
            # print("WARNING: {0} main loop candidates detected".format(len(loops)))
            if len(loops) == 2:
              loop1_length = (loops[0].end-loops[0].start+1)
              loop2_length = (loops[1].end-loops[1].start+1)
              length_diff = abs(loop1_length - loop2_length)
              if length_diff < 5:
                ## Probably doesn't matter which is used.
                loop = loops[0]
            if loop == None:
              print("ERROR: {0} main loop candidates detected, unsure which to use".format(len(loops)))

  if loop == None:
    if func_name != "":
      print("ERROR: Failed to find main loop for function '{0}'".format(func_name))
    else:
      print("ERROR: Failed to find main loop")
    if expected_ins_per_iter > 0.0:
      print("  Expected a loop of {0} instructions".format(round(expected_ins_per_iter, 2)))
    print(" Detected these loops:")
    for l_id in range(len(loops)):
      l = loops[l_id]
      print(" - {0} ( unroll = {1}, ctr step = {2} )".format(l.__str__(), l.unroll_factor, l.ctr_step))
      assembly_loop_filepath = asm_filepath + ".loop" + str(l_id)
      with open(assembly_loop_filepath, "w") as assembly_loop_out:
        loop_start = loops[l_id].start
        loop_end   = loops[l_id].end
        for i in range(loop_start, loop_end+1):
          op = operations[i]
          # assembly_loop_out.write(op.operation + "\n")
          assembly_loop_out.write(op.label + ": " + op.operation + "\n")
      print("   - written to {1}".format(l_id, assembly_loop_filepath))
    sys.exit(-1)

  loop_start = loop.start
  loop_end   = loop.end
  assembly_loop_filepath = asm_filepath + ".loop"
  # print("Main loop found, writing to "+assembly_loop_filepath)
  with open(assembly_loop_filepath, "w") as assembly_loop_out:
    for i in range(loop_start, loop_end+1):
      assembly_loop_out.write(operations[i].operation + "\n")

  return loop, assembly_loop_filepath

def count_loop_instructions(asm_loop_filepath, loop):
  operations = []
  with open(asm_loop_filepath) as assembly:
    line_num = 0
    idx = -1
    for line in assembly:
      line_num += 1
      line = line.replace('\n', '')
      idx += 1
      operation = AssemblyOperation(line, "", line_num, idx)
      operations.append(operation)

  div_counts = {}
  sqrt_counts = {}
  arith_counts = {}
  loop_count = 0
  load_count = 0
  store_count = 0
  insn_counts = {}

  def increment_count(a, i):
    if i in a:
      a[i] += 1
    else:
      a[i] = 1

  address_access_rgx = re.compile(".*\(.*\)")

  for op in operations:
    n_stores = 0
    n_loads = 0
    if op.operands != None:
      ## Look for memory loads and stores
      if not "lea" in op.instruction:
        ## Address operand of 'lea' instruction is not actually loaded.
        ## AFAIK, 'lea' is the only exception.
        l = len(op.operands)
        if l > 1:
          if address_access_rgx.match(op.operands[-1]):
            n_stores = 1
          for operand in op.operands[0:(l-1)]:
            if address_access_rgx.match(operand) and not "floatpacket" in operand:
              ## 'floatpacket' refers to a constant held in memory
              n_loads += 1

    ## Handle aliases:
    if op.instruction=="xchg" and len(op.operands)==2 and op.operands[0]=="%ax" and op.operands[0]==op.operands[1]:
      op.instruction = "nop"
      op.operands = None
    if op.instruction=="nopl":
      op.instruction = "nop"

    increment_count(insn_counts, op.instruction)

    load_count += n_loads
    store_count += n_stores

  if loop.unroll_factor > 1:
    ## For modelling, need to know instruction counts per non-unrolled iteration:
    for k in insn_counts.keys():
      insn_counts[k] /= float(loop.unroll_factor)

    ## Also scale down loads and stores:
    load_count /= float(loop.unroll_factor)
    store_count /= float(loop.unroll_factor)

  loop_stats = {}
  for k in insn_counts.keys():
    loop_stats[k] = insn_counts[k]

  loop_stats["LOADS"] = load_count
  loop_stats["STORES"] = store_count

  return loop_stats
