import os, re, copy, sys

import numpy as np

import sys
if sys.version_info[0] == 2:
  from sets import Set
  pyv = 2
elif sys.version_info[0] == 3:
  Set = set
  pyv = 3

from pprint import pprint

script_dirpath = os.path.join(os.getcwd(), os.path.dirname(__file__))

import imp
imp.load_source('utils', os.path.join(script_dirpath, "utils.py"))
from utils import *
imp.load_source('asm_parsing', os.path.join(script_dirpath, "asm_parsing.py"))
from asm_parsing import *

verbose_gbl = False

def extract_loop_kernel_from_obj(obj_filepath, compile_info, 
                                 expected_ins_per_iter=0.0, 
                                 func_name="", 
                                 avx512cd_required=False, 
                                 num_conflicts_per_iteration=0, 
                                 verbose=False):
  if not os.path.isfile(obj_filepath):
    print("ERROR: Cannot find file '" + obj_filepath + "'")
    sys.exit(-1)

  global verbose_gbl
  verbose_gbl = verbose
  
  if verbose_gbl:
    print("Analysing '{0}' for loop of length {1:.2f}".format(obj_filepath, expected_ins_per_iter))

  simd_len_requested = compile_info["SIMD len"]
  simd_failed = compile_info["SIMD failed"]
  if simd_failed:
    simd_len_actual = 1
  else:
    simd_len_actual = simd_len_requested

  (arch, asm_filepath) = obj_to_asm(obj_filepath)
  asm_obj = AssemblyObject(asm_filepath, arch, func_name)
  asm_clean_filepath = asm_filepath+".clean"

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

  if len(jump_ops) == 0:
    raise Exception("No jumps found")

  ## Write another version of assembly, removing unused line labels:
  asm_obj.generate_asm_simple_file()

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

      jmp_back = jump_op

      ## Search backwards for another jump that closely bypasses 'jmp_back'. 
      ## To be the bypass jump, 2 conditions must be met:
      ## 1 - Source position within 11 instructions before jmp_back's target
      ## 2 - Target position within 6 instructions of jmp_back's position
      forward_bypass_jump_found = False
      forward_bypass_jump = None
      threshold_pre=11
      threshold_post=6
      for i in range(jmp_back.jump_target_idx, jmp_back.jump_target_idx-threshold_pre, -1):
        if i in jump_op_indices:
          jump_op2 = [j for j in jump_ops if j.idx==i][0]

          if jump_op2.jump_target_idx < jump_op2.idx:
            # Another backward jump preceding 'jmp_back' rules it out as 
            # being a serial remainder loop
            break

          jmp_forward = jump_op2

          if (jmp_back.jump_target_idx > jmp_forward.idx) and \
             ((jmp_back.jump_target_idx - jmp_forward.idx) < threshold_pre) and \
             (jmp_forward.jump_target_idx > jmp_back.idx) and \
             ((jmp_forward.jump_target_idx - jmp_back.idx) < threshold_post):
             ## This is the forward bypass jump: 
             forward_bypass_jump_found = True
             forward_bypass_jump = jmp_forward
             break
          else:
            ## Any other type of jump immediately rules out 'jmp_back' as being 
            ## a serial remainder loop
            break

      if not forward_bypass_jump_found:
        continue

      ## Look for a kortest instruction that should closely precede the jump back:
      inner_kortest_found = False
      for i in range(jmp_back.idx-1, jmp_back.idx-5, -1):
        op = operations[i]
        if "kortest" in op.instruction:
          inner_kortest_found = True
          break
      ## Look for a kortest instruction that should precede the bypass jump:
      outer_kortest_found = False
      for i in range(forward_bypass_jump.idx-1, 0, -1):
        if i in jump_op_indices:
          ## End search
          break
        op = operations[i]
        if "kortest" in op.instruction:
          outer_kortest_found = True
          break

      serial_remainder_loop_found = forward_bypass_jump_found and inner_kortest_found and outer_kortest_found

      if serial_remainder_loop_found:
        jump_ops.remove(jmp_back)
        jump_op_indices.remove(jmp_back.idx)
        jump_target_label_indices.remove(jmp_back.jump_target_idx)
        ## UPDATE: I already have forward bypass jump:
        jump_ops.remove(forward_bypass_jump)
        jump_op_indices.remove(forward_bypass_jump.idx)
        jump_target_label_indices.remove(forward_bypass_jump.jump_target_idx)

        avx512_conflict_loops.append(jmp_back)

  avx512_conflict_loops = list(avx512_conflict_loops)
  avx512_conflict_loops.sort(key=lambda j: j.idx)

  n = len(avx512_conflict_loops)
  if n==0 and avx512_used and avx512cd_required:
    print("AVX512 used and AVX-512-CD required but no AVX-512-CD loops found.")
    print(obj_filepath)
    sys.exit(-1)
  if n!=0 and avx512_used and not avx512cd_required:
    print("AVX512 used and AVX-512-CD not required but {0} AVX-512-CD loops were found.".format(n))
    print(obj_filepath)
    sys.exit(-1)
  if num_conflicts_per_iteration > 0 and n%num_conflicts_per_iteration != 0:
    print("ERROR: Number of detected AVX-512-CD loops not a multiple of {0}: {1}".format(num_conflicts_per_iteration, n))
    print(obj_filepath)
    for l in avx512_conflict_loops:
      print(l)
    sys.exit(-1)

  jump_ops = list(jump_ops)
  jump_ops.sort(key=lambda j: j.idx)

  ## Update: ignore 'ja' instruction that closely follows a sqrt. GCC is adding these, 
  ##         I guess error detection.
  jump_ops_within_loop_pruned = []
  num_jumps_discarded = 0
  for j in jump_ops:
    discard_jump = False
    if j.instruction == "ja":
      for i in range(j.idx, j.idx-2, -1):
        if "sqrt" in operations[i].instruction:
          discard_jump = True
          num_jumps_discarded += 1
          break
    if not discard_jump:
      jump_ops_within_loop_pruned.append(j)
  jump_ops = jump_ops_within_loop_pruned

  loop_len_threshold = 5

  ## Identify backward jumps that follow a compare
  loop_jump_ops = Set()
  for jump_op in jump_ops:
    jump_idx = jump_op.idx
    jump_target_idx = label_to_idx[jump_op.operands[0]]
    if jump_target_idx < jump_idx:
      if jump_op.instruction in ["jb", "jmp"]:
        ## Is a non-conditional jump
        loop_jump_ops.add(jump_op)
      ## Seach backwards from 'jump_op' for a compare:
      for i in range(jump_idx-1, jump_target_idx-1, -1):
        if i in jump_op_indices:
          ## Another jump found before compare, so discard:
          break
        op = operations[i]
        if "cmp" in op.instruction or (len(op.instruction)>2 and op.instruction[0:3] in ["inc", "dec"]):
          loop_jump_ops.add(jump_op)
          break

  if len(loop_jump_ops) == 0:
    raise Exception("No loop jumps found")

  loop_jump_ops = list(loop_jump_ops)
  loop_jump_ops.sort(key=lambda j: (j.idx+j.jump_target_idx)/2)

  ## Discard any loop jumps that are enclosed by another larger:
  for i1 in range(len(loop_jump_ops)-1, -1, -1):
    lj1 = loop_jump_ops[i1]
    for i2 in range(len(loop_jump_ops)-1, -1, -1):
      if i1 == i2:
        continue
      lj2 = loop_jump_ops[i2]
      if lj2.idx >= lj1.idx and lj2.jump_target_idx <= lj1.jump_target_idx:
          # if verbose_gbl:
          #   print(" removing an enclosed loop jump: {0} -> {1}".format(lj1.idx, lj1.jump_target_idx))
          del loop_jump_ops[i1]
          break

  ## Next identify unbroken instruction sequences within these loops:
  jump_target_label_indices_sorted = list(jump_target_label_indices)
  jump_target_label_indices_sorted.sort()
  loops = Set()
  for loop_jump_op in loop_jump_ops:
    if verbose_gbl:
      print("")
      print("Scanning loop {0} -> {1}.".format(loop_jump_op.jump_target_idx, loop_jump_op.idx))

    loop_start_idx = loop_jump_op.jump_target_idx
    loop_end_idx = loop_jump_op.idx

    jump_ops_within_loop = [j for j in jump_ops if (j.idx >= loop_start_idx and \
                                                    j.idx < loop_end_idx and \
                                                    j.jump_target_idx >= loop_start_idx and \
                                                    j.jump_target_idx <= loop_end_idx)]

    ## I notice that with AVX-512 there are many tiny forward jumps that bypass division instructions.
    ## Discard them:
    jump_ops_within_loop_pruned = []
    length_threshold = 7
    for j in jump_ops_within_loop:
      discard_jump = False
      if (j.jump_target_idx > j.idx) and (j.jump_target_idx - j.idx <= length_threshold):
        is_bypass = False
        for i in range(j.idx+1, j.jump_target_idx):
          if "div" in operations[i].instruction or \
             "sqrt" in operations[i].instruction:
            is_bypass = True
            break
        if is_bypass:
          discard_jump = True
          if verbose_gbl:
            print("Discarding sqrt/div bypass jump: ")
            print(j)
      if not discard_jump:
        jump_ops_within_loop_pruned.append(j)
    jump_ops_within_loop = jump_ops_within_loop_pruned

    ## Discard short jumps that follow a div/sqrt and contain a call instruction:
    jump_ops_within_loop_pruned = []
    length_threshold = 15
    for j in jump_ops_within_loop:
      discard_jump = False
      is_short_bypass_jump = (j.jump_target_idx > j.idx) and (j.jump_target_idx - j.idx <= length_threshold)
      if is_short_bypass_jump:
        follows_a_sqrt_or_div = False
        for i in range(j.idx, j.idx-5, -1):
            if "div" in operations[i].instruction or \
               "sqrt" in operations[i].instruction:
               follows_a_sqrt_or_div = True
        if follows_a_sqrt_or_div:
          is_call_wrapper = False
          for i in range(j.idx+1, j.jump_target_idx):
            if "call" in operations[i].instruction:
              is_call_wrapper = True
              break
          if is_call_wrapper:
            discard_jump = True
            if verbose_gbl:
              print("Discarding call-wrapper jump: ")
              print(j)
      if not discard_jump:
        jump_ops_within_loop_pruned.append(j)
    jump_ops_within_loop = jump_ops_within_loop_pruned

    interruption_indices = Set()

    ## Find forward jumps that launch and land within the backward jump 'loop_jump_op', with the condition 
    ## that the quantity of instructions remaining outside of the 'forward bypass' is sufficient for a
    ## compute loop:
    entry_points = []
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

    jump_back_points = []
    for j in jump_ops_within_loop:
      if j.jump_target_idx < j.idx:
        jump_back_points.append(j.idx)

    interruption_indices = list(interruption_indices)
    interruption_indices += jump_back_points
    interruption_indices.sort()

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

    seq_list = []
    for s in sequences:
      seq_list.append(s)
    seq_list.sort(key=lambda s: s[0])
    if verbose_gbl:
      print("  contains {0} sequences:".format(len(sequences)))
    for s in seq_list:
      l = Loop(s[0], s[1])
      if verbose_gbl:
        print("  - " + l.__str__())
      l.simd_len = simd_len_actual
      loops.add(l)

  loops = list(loops)
  loops.sort(key=lambda l: l.start)

  ## Remove any loops that are only slightly bigger than another inside of it:
  for i in range(len(loops)-1, -1, -1):
    l1 = loops[i]
    for l2 in loops:
      if l2 == l1:
        continue
      if l2.start >= l1.start and l2.end <= l1.end:
        diff = (l2.start - l1.start) + (l1.end - l2.end)
        if diff < loop_len_threshold:
          if verbose_gbl:
            print(" removing a container loop: " + loops[i].__str__())
          del loops[i]
          break

  loops.sort(key=lambda l: l.start)

  ## Select the loop that agrees with measurement of runtime measurement of #instructions:
  loop = None

  perfect_match_loops = []
  for l in loops:
    if (l.unroll_factor!=-1) and ((l.end-l.start+1)==round(expected_ins_per_iter*l.unroll_factor)):
      perfect_match_loops.append(l)
    elif (l.unroll_factor == -1) and ((l.end-l.start+1)==round(expected_ins_per_iter)):
      perfect_match_loops.append(l)
  if len(perfect_match_loops) == 1:
    loop = perfect_match_loops[0]
    loop.unroll_factor = 1
    loop.simd_len = simd_len_actual
    if verbose_gbl:
      print("Found a perfectly-matching loop: " + loop.__str__())
  elif len(perfect_match_loops) > 1:
    if verbose_gbl:
      print("  {0} perfectly-matching loops detected".format(len(perfect_match_loops)))

  ## Maybe the target loop is unknowingly unrolled:
  if loop == None and expected_ins_per_iter >= 0.0:
    candidate_unroll_factors = [2, 4, 8, 16]
    for cuf in candidate_unroll_factors:
      if verbose_gbl:
        print("- checking if unroll_factor = {0}".format(cuf))
      unrolled_loop_candidates = []
      for l in loops:
        l_len = float(l.end-l.start+1)
        diff = abs((l_len/cuf)-expected_ins_per_iter)
        # if verbose_gbl:
        #   print("- - diff = {0}".format(diff))
        if diff < 1.0 or ("manual" in compile_info["SIMD CA scheme"].lower() and diff < 3.0):
          unrolled_loop_candidates.append(l)
      if len(unrolled_loop_candidates) == 1:
        l = unrolled_loop_candidates[0]
        l.print_loop_detailed()
        loop = l
        loop.unroll_factor = cuf
        # loop.simd_len = simd_len_actual // cuf
        loop.simd_len = simd_len_actual
        break

  ## If any of the loops match expected_ins_per_iter then select the first:
  if loop == None and expected_ins_per_iter > 0.0:
    for l in loops:
      ll = float(l.end-l.start+1)
      diff = abs(ll-expected_ins_per_iter)
      if abs(ll-expected_ins_per_iter) < 0.2:
        if verbose_gbl:
          print("Found a match with expected ins/iter")
        loop = l
        loop.unroll_factor = 1
        if simd_len_actual == 0:
          raise Exception("simd_len_actual is zero")
        loop.simd_len = simd_len_actual
        break

  scatter_loop = None
  gather_loop = None
  ## Account for gather/scatter loops, if present:
  if loop == None and "manual" in compile_info["SIMD CA scheme"].lower():
    if verbose_gbl:
      print("Making adjustments for manual CA scheme")
    ## Remove gather and/or scatter loop
    if "scatter loop present" in compile_info and compile_info["scatter loop present"]:
      ## One of these loops should be much smaller (no register spills) and be mostly memory read/write:
      expected_loads  = compile_info["scatter loop numLoads"]
      expected_stores = compile_info["scatter loop numStores"]
      expected_load_bytes  = expected_loads*8
      expected_store_bytes = expected_stores*8
      if arch == Architectures.AARCH64:
        if verbose_gbl:
          print("- scanning for scatter loop with {0} bytes loaded and {1} bytes stored".format(expected_load_bytes, expected_store_bytes))
        scatter_loop_idx = asm_obj.identify_packing_loop_idx_from_bytes(loops, expected_load_bytes, expected_store_bytes, scatter=True)
      else:
        if verbose_gbl:
          print("- scanning for scatter loop with {0} loads and {1} stores".format(expected_loads, expected_stores))
        scatter_loop_idx = asm_obj.identify_packing_loop_idx(loops, expected_loads, expected_stores)

      if not scatter_loop_idx is None:
        ## Remove loop, and reduce expected ins/iter:
        scatter_loop = loops[scatter_loop_idx]
        scatter_loop.unroll_factor = 1
        scatter_loop.simd_len = 1
        scatter_loop_niters = simd_len_actual
        if verbose_gbl:
          print(" - - removing scatter loop: " + scatter_loop.__str__())
        del loops[scatter_loop_idx]
        if expected_ins_per_iter > 0.0:
          expected_ins_per_iter -= (scatter_loop.end - scatter_loop.start + 1) * scatter_loop_niters
          if verbose_gbl:
            print(" - - expected ins/iter reduced to {0:.2f}".format(expected_ins_per_iter))

    if "gather loop present" in compile_info and compile_info["gather loop present"]:
      ## One of these loops should be much smaller (no register spills) and be mostly memory read/write:
      expected_loads = compile_info["gather loop numLoads"]
      expected_stores = compile_info["gather loop numStores"]
      expected_load_bytes = expected_loads*8
      expected_store_bytes = expected_stores*8
      if arch == Architectures.AARCH64:
        if verbose_gbl:
          print("- scanning for gather loop with {0} bytes loaded and {1} bytes stored".format(expected_load_bytes, expected_store_bytes))
        gather_loop_idx = asm_obj.identify_packing_loop_idx_from_bytes(loops, expected_load_bytes, expected_store_bytes)
      else:
        if verbose_gbl:
          print("- scanning for gather loop with {0} loads and {1} stores".format(expected_loads, expected_stores))
        gather_loop_idx = asm_obj.identify_packing_loop_idx(loops, expected_loads, expected_stores)

      gather_loop_niters_per_flux = None
      if gather_loop_idx is None:
        ## Maybe it has been unrolled ...
        unroll_factors = [2,4,8,16]
        for uf in unroll_factors:
          if uf > simd_len_requested:
            break
          print("- - rescanning with unroll factor {0}".format(uf))
          if arch == Architectures.AARCH64:
            gather_loop_idx = asm_obj.identify_packing_loop_idx_from_bytes(loops, expected_load_bytes*uf, expected_store_bytes*uf)
          else:
            gather_loop_idx = asm_obj.identify_packing_loop_idx(loops, expected_loads*uf, expected_stores*uf)
          if not gather_loop_idx is None:
            gather_loop = loops[gather_loop_idx]
            ## Maybe I mistook unrolling for vectorisations ...
            if asm_obj.get_simd_ratio(loop=gather_loop) > 0.75:
              ## > 75% SIMD instructions, must be vectorised:
              gather_loop.simd_len = uf
              gather_loop.unroll_factor = 1
            else:
              gather_loop.simd_len = 1
              gather_loop.unroll_factor = uf
            gather_loop_niters_per_flux = simd_len_actual
            gather_loop_niters_per_flux /= uf
            break

      if not gather_loop_idx is None:
        ## Remove loop, and reduce expected ins/iter:
        if gather_loop is None:
          gather_loop = loops[gather_loop_idx]
          gather_loop.simd_len = 1
          gather_loop.unroll_factor = 1
          gather_loop_niters_per_flux = simd_len_actual
        if verbose_gbl:
          print("- - removing gather loop: " + gather_loop.__str__())
        del loops[gather_loop_idx]
        if expected_ins_per_iter > 0.0:
          expected_ins_per_iter -= (gather_loop.end - gather_loop.start + 1) * gather_loop_niters_per_flux
          if verbose_gbl:
            print("- - expected ins/iter reduced to {0:.2f}".format(expected_ins_per_iter))
    if (not gather_loop is None) or (not scatter_loop is None):  
      ## Adjust for nested loops needing small number of 'admin' instructions outside:
      # nested_loop_admin_instructions = 6
      # nested_loop_admin_instructions = 10
      nested_loop_admin_instructions = 15
      if simd_failed:
        ## 'expected_ins_per_iter' will have been adjusted. Also need to adjust
        ## 'nested_loop_admin_instructions':
        nested_loop_admin_instructions /= simd_len_requested
      expected_ins_per_iter -= float(nested_loop_admin_instructions)
      if verbose_gbl:
        print("- deducted {0} admin instructions, expected ins/iter reduced to {1:.2f}".format(nested_loop_admin_instructions, expected_ins_per_iter))

    if (not gather_loop is None) and (not scatter_loop is None):
      ## Exclude any loops not inbetween gather and scatter:
      start = min(gather_loop.end,   scatter_loop.end)
      end   = max(gather_loop.start, scatter_loop.start)
      for i in range(len(loops)-1, -1, -1):
        l = loops[i]
        if l.start < start or l.end > end:
          del loops[i]

    if not scatter_loop is None:
      ## Can restrict set of candidate loops to those that fall within the
      ## backward-jump instruction that closely follows end of scatter loop
      for loop_jump_op in loop_jump_ops:
        x = loop_jump_op.idx - scatter_loop.end
        if x > 0 and x < 20:
          ## Found it!
          loops_restricted = []
          for l in loops:
            if (l.end < loop_jump_op.idx) and (l.start >= loop_jump_op.jump_target_idx):
             loops_restricted.append(l)
          if len(loops_restricted) == 0:
            raise Exception("Restriction failed, removed all loops")
          if verbose_gbl:
            print("")
            print("Restricting candidate loops to those falling within post-scatter backward-jump:")
            for l in loops_restricted:
              print(" - " + l.__str__())
          loops = loops_restricted
          break

  if loop == None and expected_ins_per_iter >= 0.0:
    ## Apply several heuristics to guess which of the detected loop is the target loop:
    if verbose_gbl:
      print("Did not find exact match for main compute loop, applying heuristics to: {0}".format(asm_filepath))

  if loop == None and avx512_used:
    ## Due to the masked inner loops that occur for write conflicts, it is 
    ## difficult to estimate exactly from assembly analysis of how many 
    ## instructions-per-iteration would be executed.
    if len(loops) == 1:
      ## Phew, just use that
      loop = loops[0] ; loop.unroll_factor = 1 ; loop.simd_len = simd_len_actual
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
        raise Exception("ERROR: No loop candidates exist after pruning those too long.")
      elif len(loops) == 1:
        ## Phew, just use that
        loop = loops[0] ; loop.unroll_factor = 1 ; loop.simd_len = simd_len_actual
      else:
        if len(loops) == 2:
          loop1_length = (loops[0].end-loops[0].start+1)
          loop2_length = (loops[1].end-loops[1].start+1)
          length_diff = abs(loop1_length - loop2_length)
          if length_diff < 5:
            ## Probably doesn't matter which is used.
            loop = loops[0] ; loop.unroll_factor = 1 ; loop.simd_len = simd_len_actual
        if loop == None:
          print("ERROR: {0} main loop candidates detected, unsure which to use".format(len(loops)))

  ## Maybe the target loop is unknowingly unrolled:
  if loop == None and expected_ins_per_iter >= 0.0:
    candidate_unroll_factors = [2, 4, 8, 16]
    for cuf in candidate_unroll_factors:
      if verbose_gbl:
        print("- checking if unroll_factor = {0}".format(cuf))
      unrolled_loop_candidates = []
      for l in loops:
        l_len = float(l.end-l.start+1)
        diff = abs((l_len/cuf)-expected_ins_per_iter)
        if diff < 1.0 or ("manual" in compile_info["SIMD CA scheme"].lower() and diff < 3.0):
          unrolled_loop_candidates.append(l)
      if len(unrolled_loop_candidates) == 1:
        l = unrolled_loop_candidates[0]
        l.print_loop_detailed()
        loop = l
        loop.unroll_factor = cuf
        loop.simd_len = simd_len_actual
        break

  ## If any of the loops match expected_ins_per_iter then select the first:
  if loop == None and expected_ins_per_iter > 0.0:
    for l in loops:
      ll = float(l.end-l.start+1)
      diff = abs(ll-expected_ins_per_iter)
      if abs(ll-expected_ins_per_iter) < 0.2:
        if verbose_gbl:
          print("Found a match with expected ins/iter")
        loop = l
        loop.unroll_factor = 1
        if simd_len_actual == 0:
          raise Exception("simd_len_actual is zero")
        loop.simd_len = simd_len_actual
        break

  ## Maybe one of the loops is a close match. If several, pick the closest:
  if loop == None and len(loops) >= 1 and expected_ins_per_iter > 0.0:
    close_match_loop = None
    close_matches = []
    for l in loops:
      loop_len = float(l.end-l.start+1)
      diff = expected_ins_per_iter - float(loop_len)
      diff_pct = abs(diff) / float(expected_ins_per_iter)
      if diff_pct > 0.5:
        ## Not even close
        continue
      close_match = False
      # if abs(diff) <= 2 or diff_pct <= 0.02:
      # if abs(diff) <= 2 or diff_pct <= 0.045:
      if diff_pct <= 0.15:
        ## 15% is a very loose tolerance, but needed as Clang and GCC 
        ## insert short conditional sequences after each sqrt that 
        ## contain a 'callq', but I suspect these are never executed. 
        ## Ideally I would REMOVE these sequences from assembly, but that needs time.
        close_match = True
      elif "manual" in compile_info["SIMD CA scheme"].lower() and diff < 20:
        ## Allow larger difference iff positive (loop smaller than expected), 
        ## to allow for additional 'admin' instructions needed for manual CA
        close_match = True
      if close_match:
        l.is_simd = asm_obj.get_simd_ratio(loop=l) > 0.33

        close_matches.append(l)

    if len(close_matches) > 0:
      if simd_len_actual > 1:
        ## Search for a close match SIMD loop:
        simd_close_match = None
        for l in close_matches:
          if l.is_simd:
            if not simd_close_match is None:
              raise Exception("Found multiple closely matching SIMD loops")
            simd_close_match = l
        if not simd_close_match is None:
          close_match_loop = simd_close_match
          close_match_loop.simd_len = simd_len_actual
          close_match_loop.unroll_factor = 1

      if close_match_loop is None:
        ## Pick the closest match:
        close_match_loop = close_matches[0]
        close_match_loop_len = float(close_match_loop.end-close_match_loop.start+1)
        for l in close_matches:
          loop_len = float(l.end-l.start+1)
          diff = expected_ins_per_iter - float(loop_len)
          if abs(diff) < abs(expected_ins_per_iter - close_match_loop_len):
            close_match_loop = l
            close_match_loop_len = loop_len
        close_match_loop.simd_len = simd_len_actual
        close_match_loop.unroll_factor = 1

    if not close_match_loop is None:
      if verbose_gbl:
        print("found a close match: " + close_match_loop.__str__())
      loop = close_match_loop

  ## Maybe user requested compiler to vectorise the loop, but simd failed and failure not detected by tool.
  ## Update: or, was vectorised at a different width than requested
  if loop == None and expected_ins_per_iter != 0.0 and simd_len_actual > 1:
    failed_simd_loop_candidates = []
    true_simd_len_candidates = [8, 4, 2, 1]
    for tsl in true_simd_len_candidates:
      if verbose_gbl:
        print("- checking if true_simd_len = {0}".format(tsl))
      if not loop is None:
        break
      for l in loops:
        if tsl == 1 and asm_obj.get_simd_ratio(l) > 0.5:
          ## This loop is vectorised, so it shouldn't have failed.
          continue
        l_len = float(l.end-l.start+1)
        diff = abs(int(expected_ins_per_iter / simd_len_actual * tsl) - l_len)
        diff_pct = diff / l_len
        if diff_pct < (1.5/100):
          failed_simd_loop_candidates.append(l)
      if len(failed_simd_loop_candidates) == 1:
        l = failed_simd_loop_candidates[0]
        l.unroll_factor = 1
        l.simd_len = tsl
        if tsl == 1:
          print(" detected one loop that would be generated if requested SIMD failed:")
          simd_failed = True
        else:
          print(" detected one loop that would be generated if actually vectorised at width {0}, not the expected {1}:".format(tslc, simd_len_actual))
        l.print_loop_detailed()
        print(" selecting this loop")
        loop = l
      elif len(failed_simd_loop_candidates) > 1:
        ## Maybe the contents of each loop candidates are near identical:
        loop_stats = None
        loops_identical = True
        for l in failed_simd_loop_candidates:
          ls = count_asm_loop_instructions(asm_clean_filepath, l)
          ls["LOADS"] += ls["LOAD_SPILLS"] ; ls["LOAD_SPILLS"] = 0
          ls["STORES"] += ls["STORE_SPILLS"] ; ls["STORE_SPILLS"] = 0
          if loop_stats is None:
            loop_stats = ls
          else:
            if ls != loop_stats:
              ## This loop is different to previous, so cannot be sure which is main compute loop
              ### ... unless difference is small
              ls_count = sum([v for v in ls.values()])
              loop_stats_count = sum([v for v in loop_stats.values()])
              diff = abs(loop_stats_count - ls_count)
              diff_pct = float(diff) / float(ls_count)
              if diff_pct > 0.015:
                print(" multiple distinct failed-simd candidate loops detected")
                loops_identical = False
                break
        if loops_identical:
          if tsl == 1:
            print(" detected multiple identical loops that would be generated if requested SIMD failed, selecting first:")
            simd_failed = True
          else:
            print(" detected multiple identical loops that would be generated if actually vectorised at width {0}, not the expected {1}, selecting first:".format(tslc, simd_len_actual))
          l = failed_simd_loop_candidates[0]
          loop = l
          loop.unroll_factor = 1
          loop.simd_len = tsl

  ## Maybe I can make an intelligent guess of the main loop:
  if loop == None and expected_ins_per_iter < 0.0:
    min_l = min([l.end-l.start+1 for l in loops])
    max_l = max([l.end-l.start+1 for l in loops])
    if float(max_l-min_l)/float(min_l) < 0.06:
      ## All detected loops are similar size, probably slightly 
      ## different compiler-generated loops of the same source-code 
      ## loop. Pick the largest loop, as this typically is the main 
      ## compute loop:
      for l in loops:
        if (l.end-l.start+1) == max_l:
          loop = l
          break

  if loop == None:
    if func_name != "":
      print("ERROR: Failed to identify primary compute loop for function '{0}' in: {1}".format(func_name, asm_clean_filepath))
    else:
      print("ERROR: Failed to identify primary compute loop in: {0}".format(asm_clean_filepath))
    if expected_ins_per_iter > 0.0:
      print(" Expected a loop of {0:.2f} instructions".format(expected_ins_per_iter))
    print(" Detected these loops:")
    for l_id in range(len(loops)):
      l = loops[l_id]
      l.print_loop_detailed()
      assembly_loop_filepath = asm_filepath + ".loop" + str(l_id)
      asm_obj.write_loop_to_file(assembly_loop_filepath, loop=loops[l_id])
      print("   - written to {1}".format(l_id, assembly_loop_filepath))
    print("")
    raise Exception("Failed to analyse assembly")

  # Perform some final sanity checks on the detected loop:
  if (not loop is None):
    if simd_failed and loop.simd_len > 1:
      raise Exception("SIMD confirmed to have failed, but loop tagged as vectorised (width 8)")

    if (loop.simd_len == 1) and asm_obj.get_simd_ratio(loop) > 0.5:
      raise Exception("Loop tagged as not vectorised, but actually is (SIMD ratio = {0})".format(asm_obj.get_simd_ratio(loop)))

    if (loop.simd_len > 1) and (asm_obj.get_simd_ratio(loop) < 0.1):
      if verbose_gbl:
        print("Selected loop is not actually vectorised (SIMD ratio = {0}). Must be unrolled instead.".format(asm_obj.get_simd_ratio(loop)))
      if loop.unroll_factor == -1:
        loop.unroll_factor = loop.simd_len
      else:
        loop.unroll_factor *= loop.simd_len
      loop.simd_len = 1

    if loop.simd_len==-1 and simd_failed:
      raise Exception("SIMD certainly failed, but loop.simd_len is still -1")
    if loop.simd_len==0:
      raise Exception("loop.simd_len is somehow zero")

  ## Write out loop to file:
  assembly_loop_filepath = asm_filepath + ".loop"
  if os.path.isfile(assembly_loop_filepath):
    os.remove(assembly_loop_filepath)

  loop_widths = [loop.simd_len*loop.unroll_factor]
  if not gather_loop is None:
    w = gather_loop.simd_len*gather_loop.unroll_factor
    if not w in loop_widths:
      loop_widths.append(w)
  if not scatter_loop is None:
    w = scatter_loop.simd_len*scatter_loop.unroll_factor
    if not w in loop_widths:
      loop_widths.append(w)
  edge_batch_size = 0
  lcm_found = False
  while not lcm_found:
    edge_batch_size += 1
    lcm_found = True
    for w in loop_widths:
      if edge_batch_size%w != 0:
        lcm_found = False
        break

  metadata = asm_obj.metadata
  if simd_len_requested > 1 and loop.simd_len != simd_len_requested:
    metadata["True SIMD len"] = loop.simd_len
    if loop.simd_len == 1:
      metadata["SIMD failed"] = True
  elif compile_info["SIMD failed"] and loop.simd_len > 1:
    ## Tool was given incorrect info, loop was actually vectorised:
    metadata["SIMD failed"] = False
  metadata["#edges per asm pass"] = edge_batch_size
  asm_obj.metadata = metadata

  if not gather_loop is None:
    lg = Loop(gather_loop.start, gather_loop.end, arch)
    try:
      niters = edge_batch_size // gather_loop.simd_len // gather_loop.unroll_factor
    except:
      raise Exception("Failed to calculate ntiers from: edge_batch_size={0}, gather_loop.simd_len={1}, gather_loop.unroll_factor={2}".format(edge_batch_size, gather_loop.simd_len, gather_loop.unroll_factor))
    if verbose_gbl:
      print("- writing out {0} gather loop iterations".format(niters))
    for i in range(0,niters):
      asm_obj.write_loop_to_file(assembly_loop_filepath, lg, append=True)

  lmain = Loop(loop.start, loop.end, arch)
  try:
    niters = edge_batch_size // loop.simd_len // loop.unroll_factor
  except:
    raise Exception("Failed to calculate ntiers from: edge_batch_size={0}, loop.simd_len={1}, loop.unroll_factor={2}".format(edge_batch_size, loop.simd_len, loop.unroll_factor))
  if niters == 0:
    raise Exception("Have calculated 0 iters from: edge_batch_size={0}, loop.simd_len={1}, loop.unroll_factor={2}".format(edge_batch_size, loop.simd_len, loop.unroll_factor))
  if verbose_gbl:
    print("- writing out {0} main loop iterations".format(niters))
  for i in range(0,niters):
    asm_obj.write_loop_to_file(assembly_loop_filepath, lmain, append=True)

  if not scatter_loop is None:
    ls = Loop(scatter_loop.start, scatter_loop.end, arch)
    niters = edge_batch_size // scatter_loop.simd_len // scatter_loop.unroll_factor
    if verbose_gbl:
      print("- writing out {0} scatter loop iterations".format(niters))
    for i in range(0,niters):
      asm_obj.write_loop_to_file(assembly_loop_filepath, ls, append=True)

  asm_obj = AssemblyObject(assembly_loop_filepath)
  asm_obj.metadata = metadata
  return asm_obj

