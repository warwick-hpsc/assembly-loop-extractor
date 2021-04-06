import re, copy, os
import ast

script_dirpath = os.path.join(os.getcwd(), os.path.dirname(__file__))

import imp
imp.load_source('utils', os.path.join(script_dirpath, "utils.py"))
from utils import *

import sys
if sys.version_info[0] == 2:
  from sets import Set
  pyv = 2
elif sys.version_info[0] == 3:
  Set = set
  pyv = 3

from enum import Enum
class Architectures(Enum):
  x86 = 1
  AARCH64 = 2
arch_to_string = {Architectures.x86:"x86", Architectures.AARCH64:"aarch64"}
string_to_arch = {v:k for k,v in arch_to_string.items()}

cmnt_line_rgx = re.compile("^ *#")
empty_line_rgx = re.compile("^[ \t]*$")
jump_ins_rgx = re.compile("^[ \t]*j")
jump_label_intel_rgx = re.compile("^\.\.B[0-9]\.[0-9]+:")
jump_label_gnu_rgx = re.compile("^\.L[0-9]+:")
jump_label_obj_rgx = re.compile("^[0-9a-z]+$")
noise_rgx = re.compile("^[\.]+[a-zA-Z]")

metadata_line = "--METADATA--"

def get_asm_arch(asm_filepath):
  global metadata_line
  arch_str = None
  with open(asm_filepath) as assembly:
    in_metadata = False
    for line in assembly:
      line = line.replace('\n', '')
      if line == metadata_line:
        in_metadata = True
      if not in_metadata:
        continue
      res = re.match("^ARCH=(.*)$", line)
      if res:
        arch_str = res.groups()[0] ; break
  if arch_str is None:
    raise Exception("Could not find ARCH variable in '{0}'".format(asm_filepath))
  arch = None
  for k,v in arch_to_string.items():
    if arch_str == v:
      arch = k ; break
  if arch is None:
    print(asm_filepath)
    raise Exception("Failed to map ARCH value '{0}' to Enum".format(arch_str))
  return arch

def obj_to_asm(obj_filepath):
  if not os.path.isfile(obj_filepath):
    print("ERROR: Cannot find file '" + obj_filepath + "'")
    sys.exit(-1)

  global metadata_line
  asm_filepath = obj_filepath + ".asm"
  raw_asm_filepath = obj_filepath + ".raw-asm"

  arch = Architectures.x86
  if os.path.isfile(raw_asm_filepath):
    for line in open(raw_asm_filepath):
      if "aarch64" in line:
        arch = Architectures.AARCH64
        break

  if os.path.isfile(asm_filepath):
    arch_present = False
    with open(asm_filepath) as assembly:
      for line in assembly:
        if re.match("^ARCH=.*", line):
          arch_present = True
          break
    if not arch_present:
      sep_command = 'echo "{0}" >> {1}'.format(metadata_line, asm_filepath)
      os.system(sep_command)
      arch_command = 'echo "ARCH={0}" >> {1}'.format(arch_to_string[arch], asm_filepath)
      os.system(arch_command)
    return (arch, asm_filepath)

  if not os.path.isfile(raw_asm_filepath):
    ## Extract assembly:
    objdump_command = "objdump -d --no-show-raw-insn {0}".format(obj_filepath)
    objdump_command += " > {0}".format(raw_asm_filepath)
    os.system(objdump_command)
    if not os.path.isfile(raw_asm_filepath):
      print("ERROR: objdump failed")
      sys.exit(-1)

  ## Re-format assembly for easier parsing:
  format_command = "cat {0}".format(raw_asm_filepath)
  format_command += ' | sed "s/^Disassembly of section/ fnc: Disassembly/g"'
  format_command += ' | sed "s/:$//g"'
  format_command += ' | grep "^ "'
  format_command += ' | grep ":"'
  format_command += ' | sed "s/^[ \t]*//g"'
  format_command += " > {0}".format(asm_filepath)
  os.system(format_command)

  sep_command = 'echo "{0}" >> {1}'.format(metadata_line, asm_filepath)
  os.system(sep_command)
  arch_command = 'echo "ARCH={0}" >> {1}'.format(arch_to_string[arch], asm_filepath)
  os.system(arch_command)

  return (arch, asm_filepath)

def clean_asm_file(asm_filepath, func_name=""):
  if func_name == "":
    return asm_filepath

  ## Attempt to find the instructions that constitute specified function name.
    
  global metadata_line
  asm_lines = []
  with open(asm_filepath, "r") as asm:
    for line in asm:
      line = line.replace('\n', '')
      if line == metadata_line:
        break
      if metadata_line in line:
        raise Exception("Metadata tail not being skipped")
      if "ARCH=" in line:
        raise Exception("Metadata tail not being skipped")
      line = line.replace('\t', ' ')
      line = re.sub(r" +", " ", line)
      line = re.sub(r"^ *", "", line)
      asm_lines.append(line)
  arch = get_asm_arch(asm_filepath)

  # Attempt to find the block of instructions relating to function
  func_lines = []

  # Possibility #1: function kernel in a separate disassembly section:
  #func_name_rgx = re.compile("^.*{0}.*$".format(func_name))
  func_name_rgx = re.compile("^.*{0}[^_].*$".format(func_name))
  func_in_separate_disassembly = False
  parse = False
  for line in asm_lines:
    if "Disassembly" in line and func_name_rgx.match(line):
      print("{0} found in separate disassembly section".format(func_name))
      func_in_separate_disassembly = True
      parse = True
    if func_in_separate_disassembly and "<" in line and (not func_name_rgx.match(line)):
      parse = False
    if parse:
      func_lines.append(line)
  ## CAUTION: when kernel is in a separate disassembly section, that 
  ##           likely means compiler failed to inline it. So that section 
  ##         should be ignored.

  # Possibility #2: kernel assembly embedded with all other assembly:
  if not func_in_separate_disassembly:
    func_first_appearance = -1
    func_last_appearance = -1
    i = -1
    for line in asm_lines:
      i+=1
      if "<" in line and func_name_rgx.match(line):
        if func_first_appearance == -1:
          func_first_appearance = i
        func_last_appearance = i
    if func_first_appearance == -1 and func_last_appearance == -1:
      raise Exception("Failed to find function '{0}' in: {1}".format(func_name, asm_filepath))
    # Keep line after last appearance:
    func_last_appearance += 1
    # print("{0} found between lines {1} and {2}".format(func_name, func_first_appearance, func_last_appearance))
    func_lines = asm_lines[func_first_appearance:(func_last_appearance+1)]
  # print("Have extracted {0} lines".format(len(func_lines)))

  # Possibility #3: kernel assembly is in a separate 'omp_outlined' section. Clang does this. 
  # Hint will be if extracted assembly ends with a 'callq' instruction to an omp_outlined section:
  if "callq" in func_lines[-2]:
    omp_first_appearance = -1
    omp_last_appearance = -1
    i = -1
    for line in asm_lines:
      i+=1
      if "<" in line and ".omp_outlined" in line:
        if omp_first_appearance == -1:
          omp_first_appearance = i
        omp_last_appearance = i
    if omp_last_appearance != -1 and omp_last_appearance > omp_first_appearance:
      ## Use this block:
      # Keep line after last appearance:
      omp_last_appearance += 1
      func_lines = asm_lines[omp_first_appearance:(omp_last_appearance+1)]

  # Now clean:
  func_lines_clean = []
  for line in func_lines:
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
    func_lines_clean.append(line)
  # print("Have {0} lines after clean".format(len(func_lines_clean)))

  asm_clean_filepath = asm_filepath + ".clean"
  with open(asm_clean_filepath, "w") as asm_out:
    for line in func_lines_clean:
      asm_out.write(line + "\n")

    asm_out.write(metadata_line+"\n")
    asm_out.write("ARCH={0}".format(arch_to_string[arch]))

  return asm_clean_filepath

def read_metadata(filepath):
  global metadata_line
  metadata = {}
  with open(filepath) as assembly:
    in_metadata = False
    for line in assembly:
      line = line.replace('\n', '')
      if line == metadata_line:
        in_metadata = True
      if not in_metadata:
        continue
      res = re.match("^(.*)=(.*)$", line)
      if res:
        k = res.groups()[0]
        v = res.groups()[1]
        if k == "ARCH":
          metadata[k] = string_to_arch[v]
        else:
          metadata[k] = ast.literal_eval(v)
  return metadata

class Loop(object):
  def __init__(self, start, end, isroot=False):
    self.start = start
    self.end = end
    self.total_length = end - start + 1
    self.real_length  = end - start + 1
    self.inner_loops = []
    self.isroot = isroot

    ## Default values to unknown. Loop detection heuristics should figure these out.
    self.ctr_step = -1
    self.unroll_factor = -1
    self.simd_len = -1

  # def write_to_file(self, filepath, append=False):
  #   global metadata_line
  #   lines = []
  #   if append:
  #     if os.path.isfile(filepath):
  #       ## Read in existing lines, discard metadata
  #       with open(filepath, "r") as infile:
  #         for line in infile:
  #           line = line.replace('\n', '')
  #           if line == metadata_line:
  #             break
  #           lines.append(line)

  #   with open(filepath, "w") as outfile:
  #     for l in lines:
  #       outfile(l + "\n")

  #     # for i in range(self.start, self.end+1):
  #     for i in range(self.start, self.end+2):
  #       op = self.operations[i]
  #       outfile.write(op.label + ": " + op.operation + "\n")

  #     outfile.write(metadata_line + "\n")
  #     outfile.write("ARCH={0}".format(arch_to_string[arch]))

  def print_loop(self, indent):
    s = ""
    if self.isroot:
      s = "ROOT"
    else:
      l = self.total_length
      s = " "*indent + "Lines {0} -> {1} ({2}) ; unroll = {3} ; SIMD len = {4}".format(self.start+1, self.end+1, l, self.unroll_factor, self.simd_len)
    for il in self.inner_loops:
      s += "\n" + il.print_loop(indent+1)
    return s

  def print_loop_detailed(self):
    loop_string = " - {0}".format(self.__str__())
    loop_string += " ( unroll = "
    if self.unroll_factor == -1:
      loop_string += "unknown"
    else:
      loop_string += str(self.unroll_factor)
    loop_string += ", ctr step = "
    if self.ctr_step == -1:
      loop_string += "unknown"
    else:
      loop_string += str(self.ctr_step)
    loop_string += " )"
    print(loop_string)

  def __str__(self):
    return self.print_loop(0)

  def __hash__(self):
    return self.end

  def __eq__(self, other):
    return (isinstance(other, Loop) and self.start == other.start and self.end == other.end)

class AssemblyOperation(object):
  def __init__(self, arch, operation, label, line_num, idx):
    self.arch = arch
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
      if "<" in operands:
        operands = operands[:operands.find("<")]
      operands = re.sub(r" ", "", operands)
      operands = re.sub(r",$", "", operands)
      bracket_depth = 0
      if arch == Architectures.AARCH64:
        if self.instruction in ["ld1", "ld1d", "ld1rd", "ld2d", "ld3d", "st1d", "st2d", "st3d"]:
          ## Unpack the first operand, makes logic much easier:
          operands = operands.replace("{", "").replace("}", "")
          if '-' in operands:
            ## Also enumerate range
            operands_array = operands.split(',')
            new_operands_array = []
            for operand in operands_array:
              if not '-' in operand:
                new_operands_array.append(operand)
              else:
                p0 = operand.split('-')[0] ; p1 = operand.split('-')[1]
                p0_comps = re.match("([a-z])([0-9]+)(.*)", p0).groups()
                p1_comps = re.match("([a-z])([0-9]+)(.*)", p1).groups()
                r0 = int(p0_comps[1]) ; r1 = int(p1_comps[1])
                new_operands_array.append(p0)
                for r in range(r0+1, r1):
                  px = p0_comps[0] + str(r) + p0_comps[2]
                  new_operands_array.append(px)
                new_operands_array.append(p1)
            operands = ','.join(new_operands_array)

      if '{' in operands:
        raise Exception("Need to handle {...} operand in: " + operation)

      ## Replace ',' characters not within parentheses with ' ':
      for i in range(len(operands)):
        if operands[i] in ['(', '[', '{']:
          bracket_depth+=1
        elif operands[i] in [')', ']', '}']:
          bracket_depth-=1
        if (operands[i]==",") and (bracket_depth==0):
          operands = operands[:i] + " " + operands[i+1:]
      self.operands = operands.split(' ')

    if not self.operands is None:
      if self.instruction == "add" and self.operands[0] == "$0xffffffffffffffff":
        ## This is an obfuscated decrement
        self.instruction = "dec"
        self.operands = self.operands[1:]

      if self.arch == Architectures.AARCH64:
        if self.instruction == "subs" and \
           self.operands[0] == self.operands[1] and \
           self.operands[2] == "#0x1":
          # This is a decrement
          self.instruction = "dec"
          self.operands = [self.operands[1]]

        # If each operand begins with 'z' (SVE reg) or 'p' (predicate reg), 
        # or '#' for constant, then instruction is SVE SIMD:
        insn_is_ARM_SVE = len(self.operands) > 0
        if len(self.operands) == 3 and \
          self.operands[0][0:2] == "{z" and \
          self.operands[1][0] == 'p' and \
          self.operands[2][0] == '[':
          insn_is_ARM_SVE = True
        elif len(self.operands) == 2 and \
          self.operands[0][0:2] == "{v" and \
          self.operands[1][0] == '[':
          insn_is_ARM_SVE = True
        else:
          if not self.operands[0][0] in  ['z', 'v', 'p']:
            insn_is_ARM_SVE = False
        if insn_is_ARM_SVE:
          self.instruction = 'v'+self.instruction

        # If each operand register begins with 'v', then instruction is NEON SIMD:
        insn_is_ARM_NEON = (not insn_is_ARM_SVE) and len(self.operands) > 0
        for op in self.operands:
          if op[0] != 'v':
            insn_is_ARM_NEON = False
            break
        if insn_is_ARM_NEON:
          self.instruction = 'v'+self.instruction

        # If instruction is a variant of 'mov', and it destination operand 
        # is memory, then append ".mem" to instruction. This is because 
        # 'address' exec unit handles this, whereas FP/ALU units handle 
        # inter-register moves:
        if "mov" in self.instruction:
          if arch == Architectures.AARCH64:
            address_access_rgx = re.compile("\[.*\]")
          else:
            address_access_rgx = re.compile(".*\(.*\)")
          if address_access_rgx.match(self.operands[-1]):
            self.instruction += ".mem"


  def __str__(self):
    s = " {0} instruction: '{1}'".format(arch_to_string[self.arch], self.instruction)
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
  def __init__(self, asm_filepath, arch=None, func_name=""):
    self.asm_filepath = asm_filepath

    self.metadata = read_metadata(asm_filepath)
    if (arch is None) and not "ARCH" in self.metadata.keys():
      raise Exception("'arch' must be passed as argument, or present in asm metadata")

    self.operations = []
    self.labels = []
    self.label_to_ins = {}
    self.label_to_idx = {}
    self.simd_ratio = None

    self.asm_clean_filepath = clean_asm_file(asm_filepath, func_name)

    self.asm_clean_numLines = 0
    if pyv == 2:
      for line in open(self.asm_clean_filepath).xreadlines():
        self.asm_clean_numLines += 1
    elif pyv == 2:
      for line in open(self.asm_clean_filepath):
        self.asm_clean_numLines += 1

    self.parse_asm()
    self.identify_jumps()

  def parse_asm(self):
    global metadata_line
    with open(self.asm_clean_filepath) as assembly:
      # print("Parsing instructions in: " + self.asm_clean_filepath)
      line_num = 0
      idx = -1
      for line in assembly:
        line = line.replace('\n', '')
        if line == metadata_line:
          break
        if metadata_line in line:
          raise Exception("Metadata tail not being skipped")

        line_num += 1

        current_label = line.split(':')[0]
        line = ':'.join(line.split(':')[1:])
        line = re.sub(r"^[ \t]*", "", line)
        idx += 1
        operation = AssemblyOperation(self.metadata["ARCH"], line, current_label, line_num, idx)
        self.operations.append(operation)

        if current_label in self.label_to_ins:
          ## Only record the first instance of label
          continue
        self.labels.append(current_label)
        self.label_to_ins[current_label] = line
        self.label_to_idx[current_label] = idx

  def __str__(self):
    return "AssemblyObject, {0} operations extracted from {1}".format(len(self.operations), self.asm_filepath)

  def identify_jumps(self):
    # print("Identifying jumps in: " + self.asm_clean_filepath)
    self.jump_ops = Set()
    self.jump_op_indices = Set()
    self.jump_target_labels = Set()
    self.jump_target_label_indices = Set()
    for i in range(len(self.operations)):
      op = self.operations[i]
      is_jump = False
      if op.instruction[0] == "j":
        is_jump = True
      elif op.instruction in ["b", "bl"] or re.match("b\.[a-z]*", op.instruction):
        is_jump = True
      elif op.instruction == "b.mi":
        raise Exception("Instruction '{0}' not detected as a jump!".format(op.instruction))
      if is_jump:
        if ((i+1)*2) == self.asm_clean_numLines:
          # print("Ignoring jump on final line")
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
          # print(" - notice: Ignoring jump on line {1} to unknown label {0}".format(jump_target_label, op.line_num))
          continue

        self.jump_target_labels.add(jump_target_label)
        jump_target_idx = self.label_to_idx[jump_target_label]
        self.jump_target_label_indices.add(jump_target_idx)

        op_copy = copy.deepcopy(op)
        op_copy.jump_target_idx = jump_target_idx
        self.jump_ops.add(op_copy)
        self.jump_op_indices.add(i)

  def count_loop_instructions(self, loop=None):
    n_loads_total = 0
    n_load_bytes_total = 0
    n_spill_loads_total = 0
    n_stores_total = 0
    n_store_bytes_total = 0
    n_spill_stores_total = 0
    insn_counts = {}

    if not loop is None:
      start = loop.start
      end = loop.end
    else:
      start = 0
      end = len(self.operations)-1

    if self.metadata["ARCH"] == Architectures.AARCH64:
      # charID_to_bytes = {'q':8, 'd':4, 'w':2, 'b':1, 'x':8}
      charID_to_bytes = {'q':16, 'd':8, 'w':4, 'x':8}
      ## Assume SVE z-registers to be 512-bits, because only A64FX implements SVE:
      charID_to_bytes['z'] = 64
      charID_to_bytes['p'] = 0 ## Treat predicate registers as not loading/storing bytes
      regID_to_lanes = {'x':1, 'v':2, 'z':8}

    for op in self.operations[start:(end+1)]:
      n_stores = 0 ; n_store_bytes = 0 ; n_store_spills = 0
      n_loads  = 0 ;  n_load_bytes = 0 ;  n_load_spills = 0
      if op.operands != None:
        ## Look for memory loads and stores
        if self.metadata["ARCH"] == Architectures.AARCH64:
          address_access_rgx = re.compile("\[.*\]")
          match = op.instruction[0:2] in ["ld", "st"] or op.instruction[0:3] in ["vld", "vst"]
          if match:
            ## Count bytes loaded/stored.
            ## Note: am assuming that predicated instructions activate all lanes.
            n_ops = len(op.operands)
            for operand in op.operands[0:(n_ops-1)]:
              if not address_access_rgx.match(operand):
                bytes = None
                if '.' in operand:
                  pieces = operand.split('.')
                  if len(pieces) == 2:
                    regID = pieces[0][0]
                    regModID = pieces[1][0]
                    n_lanes = regID_to_lanes[regID]
                    if re.match("[a-z]\[[0-9]+\]", pieces[1]):
                      ## Single lane is being accessed:
                      n_lanes = 1
                    else:
                      n_lanes = regID_to_lanes[regID]
                    bytes = n_lanes * charID_to_bytes[regModID]
                  else:
                    raise Exception("Spliiting '{0}' on '.' returned {1} pieces".format(operand, len(pieces)))
                if bytes is None:
                  regID = operand[0]
                  bytes = charID_to_bytes[regID]
                # print(" - - {0} moves {1} bytes".format(op.instruction+" "+" ".join(op.operands), bytes))
                if "ld" in op.instruction:
                  n_loads += 1 ; n_load_bytes += bytes
                else:
                  n_stores += 1 ; n_store_bytes += bytes
                # else:
                #   # raise Exception("Cannot infer #bits loaded by LD operand '{0}'".format(operand))
                #   raise Exception("Cannot infer #bits loaded by operand '{0}' (charID='{1}') of LD instruction: '{2}'".format(operand, charID, op.instruction + " " + " ".join(op.operands)))
          # elif op.instruction in ["vst1d", "vst3d"]:
          #   ## Predicated store instruction. Tricky because I should not assume all lanes are always active.
          #   ## Ignore bytes-calculation for now.
          #   n_stores += 1
          #   pass
          elif op.instruction.startswith("ld") or op.instruction.startswith("vld"):
            raise Exception("Unhandled ARM load instruction: '{0}'".format(op.instruction))
          elif op.instruction.startswith("st") or op.instruction.startswith("vst"):
            raise Exception("Unhandled ARM store instruction: '{0}'".format(op.instruction))
        else:
          ## Intel
          address_access_rgx = re.compile(".*\(.*\)")
          address_access_rgx2 = re.compile(".*[.*]")
          if not "lea" in op.instruction:
            ## Address operand of 'lea' instruction is not actually loaded.
            ## AFAIK, 'lea' is the only exception.
            l = len(op.operands)
            if l > 1:
              if address_access_rgx.match(op.operands[-1]):
                if "," in op.operands[-1]:
                  # An offset present implies this load is performing an array lookup
                  n_stores += 1
                else:
                  # No offset implies that this load is not accessing an array, which I assume 
                  # to mean the store is of a register spill
                  n_store_spills += 1
              for operand in op.operands[0:(l-1)]:
                if not "floatpacket" in operand and (address_access_rgx.match(operand) or address_access_rgx2.match(operand)):
                  ## 'floatpacket' refers to a constant held in memory
                  if "," in operand:
                    # An offset present implies this load is performing an array lookup
                    n_loads += 1
                  else:
                    # No offset implies that this load is not accessing an array, which I assume 
                    # to mean the load is of a previously-spilled register value.
                    n_load_spills += 1

      ## Handle aliases:
      if op.instruction=="xchg" and len(op.operands)==2 and op.operands[0]=="%ax" and op.operands[0]==op.operands[1]:
        op.instruction = "nop"
        op.operands = None
      if op.instruction=="nopl":
        op.instruction = "nop"

      if op.instruction in insn_counts:
        insn_counts[op.instruction] += 1
      else:
        insn_counts[op.instruction] = 1

      n_loads_total += n_loads
      n_spill_loads_total += n_load_spills
      n_load_bytes_total += n_load_bytes

      n_stores_total += n_stores
      n_spill_stores_total += n_store_spills
      n_store_bytes_total += n_store_bytes

    # Allow for faulty spill detection:
    if n_loads_total == 0 and n_spill_loads_total > 0:
      # All memory loads mis-identified as spills:
      n_loads_total = n_spill_loads_total
      n_spill_loads_total = 0
    if n_stores_total == 0 and n_spill_stores_total > 0:
      # All memory stores mis-identified as spills:
      n_stores_total = n_spill_stores_total
      n_spill_stores_total = 0

    # if (not loop is None) and loop.unroll_factor > 1:
    #   ## For modelling, need to know instruction counts per non-unrolled iteration:
    #   for k in insn_counts.keys():
    #     insn_counts[k] /= float(loop.unroll_factor)

    #   ## Also scale down loads and stores:
    #   n_loads_total /= float(loop.unroll_factor)
    #   n_spill_loads_total /= float(loop.unroll_factor)
    #   n_stores_total /= float(loop.unroll_factor)
    #   n_spill_stores_total /= float(loop.unroll_factor)

    loop_stats = {}
    for k in insn_counts.keys():
      loop_stats[k] = insn_counts[k]

    loop_stats["LOADS"] = n_loads_total
    loop_stats["LOAD_SPILLS"] = n_spill_loads_total
    loop_stats["LOAD_BYTES"] = n_load_bytes_total
    loop_stats["STORES"] = n_stores_total
    loop_stats["STORE_SPILLS"] = n_spill_stores_total
    loop_stats["STORE_BYTES"] = n_store_bytes_total

    # if (not loop is None):
    #   loop_stats["unroll_factor"] = loop.unroll_factor

    return loop_stats

  def identify_packing_loop_idx(self, loops, num_loads, num_stores):
    print("identify_packing_loop_idx(loads={0}, stores={1})".format(num_loads, num_stores))
    loop = None ; loop_idx = None ; loop_stats = None
    for l_idx in range(len(loops)):
      l = loops[l_idx]
      ls = self.count_loop_instructions(l)
      l_stores = (ls["STORES"]+ls["STORE_SPILLS"])
      l_loads  = (ls["LOADS"] +ls["LOAD_SPILLS"])
      # print(" loop at {0}: loads={1}, stores={2}".format(l.start, l_loads, l_stores))
      l_is_match = (l_stores+l_loads)/(l.end-l.start+1) > 0.5 and \
                  abs(l_loads - num_loads) <= 1 and abs(l_stores - num_stores) <= 1
      if l_is_match:
        if loop_idx is None:
          loop = l ; loop_idx = l_idx ; loop_stats = ls
        else:
          ## Keep the smaller loop:
          l_count    = sum([v for v in ls.values()])
          loop_count = sum([v for v in loop_stats.values()])
          if l_count < loop_count:
            loop = l ; loop_idx = l_idx ; loop_stats = ls
    return loop_idx

  def identify_packing_loop_idx_from_bytes(self, loops, num_load_bytes, num_store_bytes, scatter=False):
    ## Notes: where instruction set allows for safe vectorisation of scatters, detecting the
    ##        manual -gather and -scatter loops can be tricky, as compiler can partially fuse it with 
    ##        the main compute loop. Observed with AARCH64 SVE ISA.
    # print("identify_packing_loop_idx_from_bytes(load B={0}, store B={1})".format(num_load_bytes, num_store_bytes))
    loop = None ; loop_idx = None ; loop_stats = None
    loop_mem_stats = [] ## Store tuples of (idx, #loads, #stores)
    for l_idx in range(len(loops)):
      l = loops[l_idx]
      ls = self.count_loop_instructions(l)
      l_load_bytes = ls["LOAD_BYTES"]
      l_store_bytes = ls["STORE_BYTES"]
      print(" - loop at {0}: load B={1} store B={2}".format(l.start, l_load_bytes, l_store_bytes))

      l_mostly_data = (l_store_bytes+l_load_bytes)/(l.end-l.start+1) > 0.5
      if l_mostly_data and l_load_bytes>0 and l_store_bytes>0:
        loop_mem_stats.append((l_idx, l_load_bytes, l_store_bytes))
        l_matches_bytes = abs(l_load_bytes - num_load_bytes) <= 1 and abs(l_store_bytes - num_store_bytes) <= 1
        if l_matches_bytes:
          if loop_idx is None:
            loop = l ; loop_idx = l_idx ; loop_stats = ls
          else:
            ## Keep the smaller loop:
            # l_count    = sum([v for v in ls.values()])
            # loop_count = sum([v for v in loop_stats.values()])
            l_count = l.end-l.start+1
            loop_count = loop.end-loop.start+1
            if l_count < loop_count:
              loop = l ; loop_idx = l_idx ; loop_stats = ls

    if loop is None:
      ## No exact matches, so pick a close match
      close_matches = []

      tol_pct = 0.1
      # print(" - - tolerance = {0:.2f}%".format(tol_pct*100.0))
      for lst in loop_mem_stats:
        diff = abs(lst[1] - num_load_bytes) + abs(lst[2] - num_store_bytes)
        diff_pct = diff / (num_load_bytes + num_store_bytes)
        # print(" - - {0} : error = {1:.2f}%".format(lst, diff_pct*100.0))
        if diff_pct < tol_pct:
          close_matches.append(lst)
      # print(" - - {0} close matches".format(len(close_matches)))

      # if len(close_matches) == 0:
      #   ## Loosen tolerance, but also require similar load:store ratio
      #   expected_ratio = num_load_bytes / num_store_bytes
      #   tol_pct = 0.3
      #   ratio_tol_pct = 0.1
      #   for lst in loop_mem_stats:
      #     diff = abs(lst[1] - num_load_bytes) + abs(lst[2] - num_store_bytes)
      #     diff_pct = diff / (num_load_bytes + num_store_bytes)
      #     lst_ratio = lst[1] / lst[2]
      #     ratio_diff_pct = abs(lst_ratio - expected_ratio) / expected_ratio
      #     if (diff_pct < tol_pct) and (ratio_diff_pct < ratio_tol_pct):
      #       close_matches.append(lst)

      # ## Loosen tolerance. Assume that some of the expected loads+stores have 
      # ## been fused into the main compute loop.
      # expected_ratio = num_load_bytes / num_store_bytes
      # for lst in loop_mem_stats:
      #   if lst[1] > num_load_bytes or lst[2] > num_store_bytes:
      #     continue
      #   lst_ratio = lst[1] / lst[2]
      #   ratio_ratio = lst_ratio / expected_ratio
      #   print(" - - lst_ratio = {0}, expected_ratio = {1}".format(lst_ratio, expected_ratio))
      #   if ratio_ratio > 0.7 and ratio_ratio < 1.3:
      #     close_matches.append(lst)

      if len(close_matches) == 1:
        loop_idx = close_matches[0][0]
      elif len(close_matches) == 2:
        ## Scatter loop will appear later than gather loop. 
        ## I cannot think of any other way to decide, and this makes sense.
        idx0 = close_matches[0][0]
        idx1 = close_matches[1][0]
        if scatter:
          loop_idx = idx1 if loops[idx1].start>loops[idx0].start else idx0
        else:
          loop_idx = idx0 if loops[idx1].start>loops[idx0].start else idx1
      elif len(close_matches) == 0:
        pass
      else:
        raise Exception("Found {0} close matches for packing loop, need to review tolerance".format(len(close_matches)))
        ## Select closest match, in terms of total #loads and #stores
        cm_best = close_matches[0]
        for i in range(1, len(close_matches)):
          diff_b = (num_load_bytes + num_store_bytes) - (cm_best[1] + cm_best[2])
          diff_i = (num_load_bytes + num_store_bytes) - (close_matches[i][1] + close_matches[i][2])
          if abs(diff_i) < abs(diff_b):
            cm_best = close_matches[i]
        loop_idx = cm_best[0]

    return loop_idx

  def get_simd_ratio(self, loop):
    if not self.simd_ratio is None:
      return self.simd_ratio

    loop_stats = self.count_loop_instructions(loop)
    if self.metadata["ARCH"] == Architectures.AARCH64:
      loop_stats = categorise_aggregated_instructions_tally_dict(loop_stats, is_aarch64=True)
    else:
      loop_stats = categorise_aggregated_instructions_tally_dict(loop_stats, is_intel64=True)
    num_simd = 0
    num_nonsimd = 0
    for k in loop_stats:
      if "eu." in k:
        if "simd" in k.lower():
          num_simd += loop_stats[k]
        else:
          num_nonsimd += loop_stats[k]
    ratio = (num_simd/(num_simd+num_nonsimd))
    # is_simd = ratio > 0.25
    # print("num_simd = {0}, num_nonsimd={1}, ratio={2}, is_simd={3}".format(num_simd, num_nonsimd, ratio, is_simd))
    # return is_simd
    # print("num_simd = {0}, num_nonsimd={1}, ratio={2:.2f}".format(num_simd, num_nonsimd, ratio))
    return ratio

  def generate_asm_simple_file(self):
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
    return self.assembly_simple_filepath

  def write_loop_to_file(self, filepath, loop=None, append=False):
    if (not loop is None) and not isinstance(loop, Loop):
      raise Exception("loop arguments must be type Loop, not {0}".format(type(loop)))

    global metadata_line
    lines = []
    if append:
      if os.path.isfile(filepath):
        ## Read in existing lines, separate out metadata
        with open(filepath, "r") as infile:
          in_metadata = False
          for line in infile:
            line = line.replace('\n', '')
            if line == metadata_line:
              in_metadata = True
            if in_metadata:
              res = re.match("^(.*)=(.*)$", line)
              if res:
                key = res.groups()[0]
                value = res.groups()[1]
                if key == "ARCH":
                  value = string_to_arch[value]
                else:
                  value = ast.literal_eval(value)
                self.metadata[key] = value
            else:
              lines.append(line)

    with open(filepath, "w") as outfile:
      for l in lines:
        outfile.write(l + "\n")

      for i in range(loop.start, loop.end+1):
        op = self.operations[i]
        outfile.write(op.label + ": " + op.operation + "\n")

      outfile.write(metadata_line + "\n")
      # outfile.write("ARCH={0}".format(arch_to_string[self.arch]))
      for key in self.metadata.keys():
        value = self.metadata[key]
        if key == "ARCH":
          value = arch_to_string[value]
        outfile.write("{0}={1}\n".format(key, value))


def count_asm_loop_instructions(asm_loop_filepath, loop=None):
  global metadata_line

  operations = []
  arch = get_asm_arch(asm_loop_filepath)
  with open(asm_loop_filepath) as assembly:
    line_num = 0
    idx = -1
    for line in assembly:
      line = line.replace('\n', '')
      if line == metadata_line:
        break

      line_num += 1
      idx += 1

      if not loop is None:
        if idx < loop.start:
          continue
        if idx > loop.end:
          break

      if re.match("^[\w]+:", line):
        ## Line starts with a label, remove it:
        line = ':'.join(line.split(':')[1:])
        line = re.sub(r"^[ \t]*", "", line)

      operation = AssemblyOperation(arch, line, "", line_num, idx)
      operations.append(operation)

    if arch is None:
      raise Exception("Could not extract ARCH from asm file, should be at tail: '{0}'".format(asm_loop_filepath))

  loop_count = 0
  load_count = 0
  load_spill_count = 0
  store_count = 0
  store_spill_count = 0
  insn_counts = {}

  if arch == Architectures.AARCH64:
    address_access_rgx = re.compile("\[.*\]")
  else:
    address_access_rgx = re.compile(".*\(.*\)")
    # address_access_rgx2 = re.compile(".*[.*]")
    ## Untested, but surely if aarch64 needs '['' escaped, then
    ## so does intel:
    address_access_rgx2 = re.compile(".*\[.*\]")

  for op in operations:
    # print(op.instruction)
    n_stores = 0
    n_store_spills = 0
    n_loads = 0
    n_load_spills = 0
    if op.operands != None:
      ## Look for memory loads and stores
      if arch == Architectures.AARCH64:
        ## Is load or store - which depends on instruction
        if op.instruction.startswith("ld") or op.instruction.startswith("vld"):
          n_loads += 1
          if op.instruction == "ldp" or op.instruction == "vldp":
            # Loads a pair, so increment again:
            n_loads += 1
        elif op.instruction.startswith("st") or op.instruction.startswith("vst"):
          n_stores += 1
      else:
        ## Intel
        if not "lea" in op.instruction:
          ## Address operand of 'lea' instruction is not actually loaded.
          ## AFAIK, 'lea' is the only exception.
          l = len(op.operands)
          if l > 1:
            if address_access_rgx.match(op.operands[-1]):
              if "," in op.operands[-1]:
                # An offset present implies this load is performing an array lookup
                n_stores += 1
              else:
                # No offset implies that this load is not accessing an array, which I assume 
                # to mean the store is of a register spill
                n_store_spills += 1
            for operand in op.operands[0:(l-1)]:
              if not "floatpacket" in operand and (address_access_rgx.match(operand) or address_access_rgx2.match(operand)):
                ## 'floatpacket' refers to a constant held in memory
                if "," in operand:
                  # An offset present implies this load is performing an array lookup
                  n_loads += 1
                else:
                  # No offset implies that this load is not accessing an array, which I assume 
                  # to mean the load is of a previously-spilled register value.
                  n_load_spills += 1

    ## Handle aliases:
    if op.instruction=="xchg" and len(op.operands)==2 and op.operands[0]=="%ax" and op.operands[0]==op.operands[1]:
      op.instruction = "nop"
      op.operands = None
    if op.instruction=="nopl":
      op.instruction = "nop"

    if op.instruction in insn_counts:
      insn_counts[op.instruction] += 1
    else:
      insn_counts[op.instruction] = 1

    load_count += n_loads
    load_spill_count += n_load_spills
    store_count += n_stores
    store_spill_count += n_store_spills

  # Allow for faulty spill detection:
  if load_count == 0 and load_spill_count > 0:
    # All memory loads mis-identified as spills:
    load_count = load_spill_count
    load_spill_count = 0
  if store_count == 0 and store_spill_count > 0:
    # All memory stores mis-identified as spills:
    store_count = store_spill_count
    store_spill_count = 0

  # if (not loop is None) and loop.unroll_factor > 1:
  #   ## For modelling, need to know instruction counts per non-unrolled iteration:
  #   for k in insn_counts.keys():
  #     insn_counts[k] /= float(loop.unroll_factor)

  #   ## Also scale down loads and stores:
  #   load_count /= float(loop.unroll_factor)
  #   load_spill_count /= float(loop.unroll_factor)
  #   store_count /= float(loop.unroll_factor)
  #   store_spill_count /= float(loop.unroll_factor)

  loop_stats = {}
  for k in insn_counts.keys():
    loop_stats[k] = insn_counts[k]

  loop_stats["LOADS"] = load_count
  loop_stats["LOAD_SPILLS"] = load_spill_count
  loop_stats["STORES"] = store_count
  loop_stats["STORE_SPILLS"] = store_spill_count

  # if (not loop is None):
  #   loop_stats["unroll_factor"] = loop.unroll_factor

  return loop_stats



