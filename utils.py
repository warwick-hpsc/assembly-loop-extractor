import pandas as pd
import os, re

import sys
pyv = sys.version_info[0]
if pyv == 2:
  from sets import Set
elif pyv == 3:
  Set = set

utils_script_dirpath = os.path.dirname(os.path.realpath(__file__))

class UnknownInstruction(Exception):
  def __init__(self, insn_name, occurence_count):
    message = "No exec unit found for insn '{0}' which occurs {1} times".format(insn_name, occurence_count)
    super(UnknownInstruction, self).__init__(message)

def safe_pd_filter(df, field, value):
  if not field in df.columns.values:
    print("WARNING: field '{0}' not in df".format(field))
    return df

  if isinstance(value, list):
    if len(value) == 0:
      raise Exception("safe_pd_filter() passed an empty list of values")
    else:
      f = df[field]==value[0]
      for i in range(1,len(value)):
        f = np.logical_or(f, df[field]==value[i])
      df = df[f]
  else:
    df = df[df[field]==value]

  if len(Set(df[field])) == 1:
    df = df.drop(field, axis=1)

  nrows = df.shape[0]
  if nrows == 0:
    raise Exception("No rows left after filter: '{0}' == '{1}'".format(field, value))
  return df

def load_insn_eu_mapping(is_aarch64=False, is_intel64=False):
  if is_aarch64:
    exec_unit_mapping_filepath = os.path.join(utils_script_dirpath, "ARM-instructions.csv")
  elif is_intel64:
    exec_unit_mapping_filepath = os.path.join(utils_script_dirpath, "Intel-instructions.csv")
  else:
    raise Exception("Specifc whether architecutre is AARCH64 or Intel64")
  df = pd.read_csv(exec_unit_mapping_filepath)

  exec_unit_mapping = {}
  for index,row in df.iterrows():
    eu = row["exec_unit"]
    if not eu in exec_unit_mapping:
      exec_unit_mapping[eu] = [row["instruction"]]
    else:
      exec_unit_mapping[eu].append(row["instruction"])

  return exec_unit_mapping

def map_insn_to_exec_unit(insn, mapping):
  exec_units = mapping.keys()
  for eu in exec_units:
    if insn in mapping[eu]:
      return eu

  for eu in exec_units:
    for eu_insn in mapping[eu]:
      if re.match("^"+eu_insn+"$", insn):
        return eu

  return ""

def categorise_aggregated_instructions_tally_csv(tally_filepath, is_aarch64=False, is_intel64=False):
  print("Categorising aggregated instructions in file: " + tally_filepath)

  if is_aarch64:
    eu_mapping = load_insn_eu_mapping(is_aarch64=True)
  elif is_intel64:
    eu_mapping = load_insn_eu_mapping(is_intel64=True)
  else:
    eu_mapping = load_insn_eu_mapping()

  exec_units = eu_mapping.keys()
  eu_classes = ["eu."+eu for eu in exec_units]

  insn_tally = pd.read_csv(tally_filepath, keep_default_na=False)

  insn_colnames = [c for c in insn_tally.columns.values if c.startswith("insn.")]

  eu_tally = insn_tally.copy().drop(insn_colnames, axis=1)
  for euc in eu_classes:
    eu_tally[euc] = 0
  eu_tally["mem.loads"] = 0
  eu_tally["mem.stores"] = 0
  # eu_tally["mem.spills"] = 0
  eu_tally["mem.load_spills"] = 0
  eu_tally["mem.store_spills"] = 0

  for insn_cn in insn_colnames:
    insn = '.'.join(insn_cn.split('.')[1:]).lower()
    count = insn_tally[insn_cn]

    if insn == "loads":
      eu_tally["mem.loads"] += count
      continue
    elif insn == "stores":
      eu_tally["mem.stores"] += count
      continue
    # elif insn == "spills":
    #   eu_tally["mem.spills"] += count
    #   continue
    elif insn == "load_spills":
      eu_tally["mem.load_spills"] += count
      continue
    elif insn == "store_spills":
      eu_tally["mem.store_spills"] += count
      continue
    elif insn in ["load_bytes", "store_bytes"]:
      ## Ignore
      continue

    eu = map_insn_to_exec_unit(insn, eu_mapping)
    exec_unit_found = eu != ""
    if not exec_unit_found:
      raise UnknownInstruction(insn, count.values.max())
    eu_tally["eu."+eu] += count

  # ## Current Intel documentation does not describe how AVX512 instructions are scheduled to 
  # ## execution ports, so for now merge with other categories:
  # eu_tally["eu.simd_alu"] = eu_tally["eu.simd_alu"] + eu_tally["eu.avx512_alu"]
  # eu_tally = eu_tally.drop("eu.avx512_alu", axis=1)
  # eu_tally["eu.simd_shuffle"] = eu_tally["eu.simd_shuffle"] + eu_tally["eu.avx512_shuffle"]
  # eu_tally = eu_tally.drop("eu.avx512_shuffle", axis=1)
  # eu_tally["eu.fp_mov"] = eu_tally["eu.fp_mov"] + eu_tally["eu.avx512_misc"]
  # eu_tally = eu_tally.drop("eu.avx512_misc", axis=1)

  # ## Further merging of categories for better model fitting:
  # eu_tally["eu.fp_mov"] = eu_tally["eu.fp_mov"] + eu_tally["eu.simd_shuffle"]
  # eu_tally = eu_tally.drop("eu.simd_shuffle", axis=1)

  if "eu.DISCARD" in eu_tally.keys():
    del eu_tally["eu.DISCARD"]

  if "kernel" in eu_tally.columns.values:
    if "compute_flux_edge" in Set(eu_tally["kernel"]) and "indirect_rw" in Set(eu_tally["kernel"]):
      ## Good, have enough data to distinguish between spill-induced L1 loads/stores and main memory loads/stores. 
      ## Can address situations where assembly-loop-extractor failed to identify spills:
      rw_data = safe_pd_filter(eu_tally, "kernel", "indirect_rw")
      if rw_data.shape[0] == eu_tally[eu_tally["kernel"]=="compute_flux_edge"].shape[0]:
        ## Safe to merge:
        rw_data = rw_data.drop(columns=[c for c in rw_data.columns if c.startswith("eu.")])
        rw_data = rw_data.rename(columns={c:c+".rw" for c in rw_data.columns if c.startswith("mem.")})
        eu_tally = eu_tally.merge(rw_data)
        f = eu_tally["mem.load_spills"]==0
        eu_tally.loc[f,"mem.load_spills"] = eu_tally.loc[f,"mem.loads"] - eu_tally.loc[f,"mem.loads.rw"]
        eu_tally.loc[f,"mem.loads"] = eu_tally.loc[f,"mem.loads.rw"]
        f = eu_tally["mem.store_spills"]==0
        eu_tally.loc[f,"mem.store_spills"] = eu_tally.loc[f,"mem.stores"] - eu_tally.loc[f,"mem.stores.rw"]
        eu_tally.loc[f,"mem.stores"] = eu_tally.loc[f,"mem.stores.rw"]
        eu_tally = eu_tally.drop(columns=[c for c in eu_tally.columns if c.endswith(".rw")])

  return eu_tally

def categorise_aggregated_instructions_tally_dict(tally, is_aarch64=False, is_intel64=False):
  if is_aarch64:
    eu_mapping = load_insn_eu_mapping(is_aarch64=True)
  elif is_intel64:
    eu_mapping = load_insn_eu_mapping(is_intel64=True)
  else:
    eu_mapping = load_insn_eu_mapping()

  exec_units = eu_mapping.keys()
  eu_classes = ["eu."+eu for eu in exec_units]

  eu_tally = {}
  for euc in eu_classes:
    eu_tally[euc] = 0
  eu_tally["mem.loads"] = 0
  eu_tally["mem.stores"] = 0
  eu_tally["mem.load_spills"] = 0
  eu_tally["mem.store_spills"] = 0

  for insn in tally.keys():
    count = tally[insn]

    insn = insn.lower()

    if insn == "loads":
      eu_tally["mem.loads"] += count
      continue
    elif insn == "stores":
      eu_tally["mem.stores"] += count
      continue
    elif insn == "load_spills":
      eu_tally["mem.load_spills"] += count
      continue
    elif insn == "store_spills":
      eu_tally["mem.store_spills"] += count
      continue
    elif insn in ["load_bytes", "store_bytes"]:
      ## Ignore
      continue

    eu = map_insn_to_exec_unit(insn, eu_mapping)
    exec_unit_found = eu != ""
    if not exec_unit_found:
      raise UnknownInstruction(insn, count)
    eu_tally["eu."+eu] += count

  if "eu.DISCARD" in eu_tally.keys():
    del eu_tally["eu.DISCARD"]

  if "eu.address" in eu_tally.keys():
    del eu_tally["eu.address"]

  return eu_tally
