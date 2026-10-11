"""Independently decode owned ELF exception metadata on all three ISAs.

These source-authored fixtures check static Itanium/DWARF object contracts.
They do not execute an unwinder, import an upstream engine, qualify dynamic
alloca/interposition/JIT publication, or prove dependency/runtime closure.
The ELF, DWARF and LSDA readers below do not call the production decoders.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SDK = Path.home() / ".cache/ostadix-toolchains/llvm-22.1.6/sdk/LLVM-22.1.6-Linux-X64/bin"
PROFILES = {
    "x86_64": ("x86_64-unknown-none", "x86_64-unknown-none", [], 62, 1, 6, 7, 16),
    "aarch64": ("aarch64-unknown-none", "aarch64-unknown-none", [], 183, 257, 29, 31, 30),
    "riscv64": ("riscv64-unknown-none", "riscv64-unknown-none-elf", ["-march=rv64gc", "-mabi=lp64"], 243, 2, 8, 2, 1),
}
LAYOUT = "e-p:64:64-i64:64-i128:128-n32:64-S128"
PERSONALITY = "eh_object_personality"
TYPEINFOS = tuple(f"eh_type_{i:03}" for i in range(130))
TYPE_ALIAS = "eh_type_alias"
EH_NAMES = ("eh_ordered", "eh_cleanup", "eh_catchall", "eh_empty_filter", "eh_named_filter", "eh_any", "eh_nodedup")


def artifact(path):
    path = Path(path).resolve()
    data = path.read_bytes()
    return {"path": str(path), "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read_leb(data, cursor, signed=False, limit=None):
    """Standard LEB reader; a cursor points AFTER the complete encoded value."""
    bound = len(data) if limit is None else min(len(data), limit)
    result, shift = 0, 0
    for _ in range(10):
        require(cursor < bound, "truncated LEB value")
        byte = data[cursor]; cursor += 1
        result |= (byte & 127) << shift
        shift += 7
        if not byte & 128:
            if signed and byte & 64:
                result -= 1 << shift
            return result, cursor
    raise ValueError("oversized LEB value")


def operand(identifier):
    return {"kind": "value", "id": identifier}


def integer(value, ty=2):
    return {"kind": "int", "ty": ty, "bits": str(value)}


def symbol(name):
    return {"kind": "symbol", "ty": 3, "name": name}


def signature(params, result=2, variadic=False):
    return {"params": params, "result": result, "abi": "c", "variadic": variadic}


def source_clauses(name):
    """Ordered source meaning, independent of table offsets or selector IDs."""
    if name == "eh_cleanup": return [], True
    if name == "eh_catchall": return [("catch", None)], False
    if name == "eh_empty_filter": return [("filter", ())], False
    if name == "eh_named_filter": return [("filter", (TYPEINFOS[0], TYPEINFOS[129], TYPEINFOS[0]))], False
    if name in {"eh_any", "eh_nodedup"}:
        return [("catch", TYPE_ALIAS), ("filter", (TYPEINFOS[129],)), ("catch", None)], True
    return ([*( ("catch", name) for name in TYPEINFOS), ("catch", TYPE_ALIAS),
             ("filter", (TYPEINFOS[0], TYPEINFOS[127], TYPEINFOS[129], TYPEINFOS[0], TYPE_ALIAS)),
             ("filter", ()), ("catch", None)], True)


def fixture(isa, source_sha):
    call_sig = signature([2] * 16)
    args = [operand(0), *[integer(i) for i in range(1, 16)]]
    functions = []
    for name in EH_NAMES:
        clauses, cleanup = source_clauses(name)
        translated = []
        for kind, value in clauses:
            translated.append({"kind": kind, **({"typeinfo": {"kind": "null", "ty": 3} if value is None else symbol(value)}
                               if kind == "catch" else {"typeinfos": [symbol(item) for item in value]})})
        function = {
            "name": name, "linkage": "external", "signature": signature([2, 3]),
            "params": [{"id": 0, "ty": 2}, {"id": 1, "ty": 3}], "entry": 10,
            "exception_handling": {"model": "itanium_dwarf_v1", "personality": symbol(PERSONALITY)},
            "blocks": [
                {"id": 10, "instructions": [
                    {"result": {"id": 5, "ty": 3}, "operation": {"op": "alloca", "size": 8193 if name == "eh_ordered" else 12288, "alignment": 16}},
                    {"result": {"id": 6, "ty": 2}, "operation": {"op": "call", "callee": symbol("eh_may_throw"), "signature": call_sig, "args": args}},
                ], "terminator": {"op": "invoke", "callee": symbol("eh_may_throw"), "signature": call_sig,
                                    "args": args, "result": {"id": 20, "ty": 2}, "normal": 20, "unwind": 40}},
                {"id": 20, "instructions": [{"result": {"id": 21, "ty": 2}, "operation": {
                    "op": "phi", "incoming": [{"block": 10, "value": operand(20)}]}}],
                 "terminator": {"op": "invoke", "callee": operand(1), "signature": call_sig,
                                "args": [operand(21), *[integer(i + 16) for i in range(15)]],
                                "result": {"id": 30, "ty": 2}, "normal": 30, "unwind": 40}},
                {"id": 30, "instructions": [], "terminator": {"op": "return", "value": operand(30)}},
                {"id": 40, "instructions": [
                    {"result": {"id": 41, "ty": 2}, "operation": {"op": "phi", "incoming": [
                        {"block": 10, "value": integer(0)}, {"block": 20, "value": operand(21)}]}},
                    {"result": {"id": 42, "ty": 4}, "operation": {"op": "landing_pad", "cleanup": cleanup, "clauses": translated}},
                    {"result": {"id": 43, "ty": 5}, "operation": {"op": "eh_type_id", "typeinfo": symbol(TYPEINFOS[129])}},
                ], "terminator": {"op": "resume", "value": operand(42)}},
            ],
        }
        # Cleanup-only retains an omitted type table; no selector query there.
        if name == "eh_cleanup": function["blocks"][3]["instructions"].pop()
        if name == "eh_any": function["comdat"] = "eh_any_key"
        if name == "eh_nodedup": function["comdat"] = "eh_nodedup_key"
        functions.append(function)
    functions += [
        {"name": "eh_cold", "linkage": "external", "signature": signature([2]), "params": [{"id": 0, "ty": 2}],
         "entry": 10, "blocks": [{"id": 10, "instructions": [], "terminator": {"op": "return", "value": operand(0)}}]},
        {"name": "eh_may_throw", "linkage": "external", "signature": call_sig, "params": [{"id": i, "ty": 2} for i in range(16)], "entry": None, "blocks": []},
        {"name": PERSONALITY, "linkage": "external", "signature": signature([], 5, True), "params": [], "entry": None, "blocks": []},
        {"name": "_Unwind_Resume", "linkage": "external", "signature": signature([3], 0), "params": [{"id": 0, "ty": 3}], "entry": None, "blocks": []},
    ]
    globals_ = [{"name": name, "ty": 2, "linkage": "external", "alignment": 8, "constant": True, "thread_local": False,
                 "initializer": {"bytes": list(struct.pack("<Q", i + 1)), "relocations": []}} for i, name in enumerate(TYPEINFOS)]
    for name, target in (("eh_cold_address", "eh_cold_alias"), ("eh_type_address", TYPE_ALIAS)):
        globals_.append({"name": name, "ty": 3, "linkage": "external", "alignment": 8, "constant": True, "thread_local": False,
                         "initializer": {"bytes": [0] * 8, "relocations": [{"offset": 0, "width": 64, "symbol": target, "addend": 0}]}})
    return {
        "format": "ocore-native-module-v1", "name": "independent-static-eh-object-fixture",
        "target": {"triple": PROFILES[isa][0], "data_layout": LAYOUT, "pointer_bits": 64, "little_endian": True,
                   "abi": "lp64" if isa == "riscv64" else None}, "semantics": "llvm_defined_behavior_v1",
        "types": [{"kind": "void"}, {"kind": "int", "bits": 1}, {"kind": "int", "bits": 64},
                  {"kind": "pointer", "address_space": 0}, {"kind": "struct", "fields": [3, 5], "packed": False},
                  {"kind": "int", "bits": 32}, {"kind": "function", "signature": signature([2])}],
        "globals": globals_, "functions": functions,
        "aliases": [{"name": "eh_cold_alias", "ty": 6, "aliasee": "eh_cold", "linkage": "external"},
                    {"name": TYPE_ALIAS, "ty": 2, "aliasee": TYPEINFOS[0], "linkage": "external"}],
        "comdats": [{"name": "eh_any_key", "selection": "any"}, {"name": "eh_nodedup_key", "selection": "no_deduplicate"}],
        "provenance": {"input_sha256": source_sha, "frontend": "source-authored-structural-fixture", "frontend_version": "1",
                       "importer": "none", "importer_version": "1", "source_function_count": len(functions),
                       "source_global_count": len(globals_), "source_alias_count": 2, "referenced_comdat_count": 2, "refinements": []},
    }


def llvm_counterpart(isa):
    """Keep a complete LLVM source counterpart for a later real importer gate."""
    lines = [f'target triple = "{PROFILES[isa][1]}"', f'target datalayout = "{LAYOUT}"',
             "$eh_any_key = comdat any", "$eh_nodedup_key = comdat nodeduplicate"]
    lines += [f"@{name} = constant i64 {i + 1}, align 8" for i, name in enumerate(TYPEINFOS)]
    lines += [f"@{TYPE_ALIAS} = alias i64, ptr @{TYPEINFOS[0]}", "@eh_cold_alias = alias i64 (i64), ptr @eh_cold",
              "@eh_cold_address = constant ptr @eh_cold_alias, align 8", f"@eh_type_address = constant ptr @{TYPE_ALIAS}, align 8",
              "declare i32 @eh_object_personality(...)", "declare void @_Unwind_Resume(ptr)",
              "declare i32 @llvm.eh.typeid.for.p0(ptr)", "declare i64 @eh_may_throw(" + ", ".join(["i64"] * 16) + ")",
              "define i64 @eh_cold(i64 %value) { ret i64 %value }"]
    for name in EH_NAMES:
        clauses, cleanup = source_clauses(name)
        group = " comdat($eh_any_key)" if name == "eh_any" else " comdat($eh_nodedup_key)" if name == "eh_nodedup" else ""
        args = ", ".join(["i64 %value", *[f"i64 {i}" for i in range(1, 16)]])
        lines += [f"define i64 @{name}(i64 %value, ptr %callback){group} personality ptr @{PERSONALITY} {{", "entry:",
                  f"  %local = alloca [{8193 if name == 'eh_ordered' else 12288} x i8], align 16",
                  f"  %ordinary = call i64 @eh_may_throw({args})", f"  %first = invoke i64 @eh_may_throw({args}) to label %normal1 unwind label %landing",
                  "normal1:", "  %normal_value = phi i64 [ %first, %entry ]",
                  "  %second = invoke i64 %callback(" + ", ".join(["i64 %normal_value", *[f"i64 {i + 16}" for i in range(15)]]) + ") to label %normal2 unwind label %landing",
                  "normal2:", "  ret i64 %second", "landing:", "  %previous = phi i64 [ 0, %entry ], [ %normal_value, %normal1 ]",
                  "  %exception = landingpad { ptr, i32 }" + (" cleanup" if cleanup else "")]
        for kind, value in clauses:
            lines.append("    catch ptr " + ("null" if value is None else "@" + value) if kind == "catch" else
                         "    filter [" + str(len(value)) + " x ptr] " + ("[" + ", ".join("ptr @" + item for item in value) + "]" if value else "zeroinitializer"))
        if name != "eh_cleanup": lines.append(f"  %typeid = call i32 @llvm.eh.typeid.for.p0(ptr @{TYPEINFOS[129]})")
        lines += ["  resume { ptr, i32 } %exception", "}"]
    return "\n".join(lines) + "\n"


class Elf:
    """ELF64 section/symbol/RELA reader with no native-runtime dependency."""
    def __init__(self, data):
        self.data = bytes(data)
        require(self.data[:6] == b"\x7fELF\x02\x01", "expected little-endian ELF64")
        header = struct.unpack_from("<HHIQQQIHHHHHH", self.data, 16)
        self.machine, shoff, shentsize, shnum, shstr = header[1], header[5], header[10], header[11], header[12]
        require(header[0] == 1 and shentsize == 64 and shnum > 0, "expected ELF64 relocatable section inventory")
        require(shoff + shnum * 64 <= len(self.data), "truncated ELF section inventory")
        self.sections = []
        for i in range(shnum):
            entry = struct.unpack_from("<IIQQQQIIQQ", self.data, shoff + 64 * i)
            name, kind, flags, address, offset, size, link, info, alignment, entsize = entry
            require(kind == 8 or offset + size <= len(self.data), "truncated ELF section")
            self.sections.append(dict(index=i, name_offset=name, kind=kind, flags=flags, address=address, offset=offset,
                                      size=size, link=link, info=info, alignment=alignment, entsize=entsize, header=shoff + 64 * i))
        names = self.section_data(shstr)
        for section in self.sections: section["name"] = self.string(names, section["name_offset"])
        self.symbols, self.relocations = [], {}
        symtabs = [s for s in self.sections if s["kind"] == 2]
        require(len(symtabs) == 1, "exactly one ELF symbol table required")
        table = symtabs[0]; strings = self.section_data(table["link"])
        require(table["entsize"] == 24 and table["size"] % 24 == 0, "malformed symbol table")
        for cursor in range(table["offset"], table["offset"] + table["size"], 24):
            name, info, other, section, value, size = struct.unpack_from("<IBBHQQ", self.data, cursor)
            self.symbols.append(dict(name=self.string(strings, name), info=info, other=other, section=section, value=value, size=size, file_offset=cursor))
        for section in self.sections:
            if section["kind"] == 4:
                require(section["link"] == table["index"] and section["entsize"] == 24 and section["size"] % 24 == 0, "malformed RELA inventory")
                entries = self.relocations.setdefault(section["info"], {})
                for cursor in range(section["offset"], section["offset"] + section["size"], 24):
                    offset, info, addend = struct.unpack_from("<QQq", self.data, cursor)
                    require(offset not in entries and info >> 32 < len(self.symbols), "duplicate/invalid relocation")
                    entries[offset] = {"offset": offset, "kind": info & 0xffffffff, "symbol": info >> 32,
                                       "addend": addend, "file_offset": cursor, "rela_section": section["index"]}
        self.named = {s["name"]: s for s in self.symbols if s["name"]}

    @staticmethod
    def string(data, offset):
        require(offset < len(data), "string offset out of range")
        end = data.find(b"\0", offset); require(end >= 0, "unterminated ELF string")
        return data[offset:end].decode()

    def section_data(self, index):
        section = self.sections[index]
        require(section["kind"] != 8, "NOBITS has no file bytes")
        return self.data[section["offset"]:section["offset"] + section["size"]]

    def relocation(self, section, offset, kind=None):
        relocation = self.relocations.get(section, {}).get(offset)
        require(relocation is not None, f"missing relocation at section {section}+{offset:#x}")
        require(kind is None or relocation["kind"] == kind, "wrong relocation width/kind")
        return relocation

    def resolve(self, relocation):
        target = self.symbols[relocation["symbol"]]
        return target["section"], target["value"] + relocation["addend"]

    def groups(self):
        result = []
        for section in self.sections:
            if section["kind"] == 17:
                data = self.section_data(section["index"])
                require(len(data) >= 8 and len(data) % 4 == 0, "malformed group")
                words = struct.unpack("<" + "I" * (len(data) // 4), data)
                require(section["info"] < len(self.symbols), "group signature absent")
                result.append({"key": self.symbols[section["info"]]["name"], "flags": words[0], "members": words[1:], "section": section["index"]})
        return result


def cfi_rows(data, initial, code_align, data_align, default=None):
    """Execute standard DW_CFA rows, including remember/restore at returns."""
    cursor, pc = 0, 0
    state = copy.deepcopy(initial); original = copy.deepcopy(default or initial)
    rows, saved = {0: copy.deepcopy(state)}, []
    while cursor < len(data):
        op = data[cursor]; cursor += 1
        major, low = op & 0xc0, op & 0x3f
        if major == 0x40: pc += low * code_align
        elif major == 0x80:
            offset, cursor = read_leb(data, cursor); state["rules"][low] = ("offset", offset * data_align)
        elif major == 0xc0:
            if low in original["rules"]: state["rules"][low] = original["rules"][low]
            else: state["rules"].pop(low, None)
        elif op == 0: pass
        elif op in (2, 3, 4):
            width = {2: 1, 3: 2, 4: 4}[op]
            require(cursor + width <= len(data), "truncated DW_CFA advance")
            pc += int.from_bytes(data[cursor:cursor + width], "little") * code_align; cursor += width
        elif op in (5, 17):
            reg, cursor = read_leb(data, cursor); offset, cursor = read_leb(data, cursor, op == 17)
            state["rules"][reg] = ("offset", offset * data_align)
        elif op == 6:
            reg, cursor = read_leb(data, cursor)
            if reg in original["rules"]: state["rules"][reg] = original["rules"][reg]
            else: state["rules"].pop(reg, None)
        elif op in (7, 8):
            reg, cursor = read_leb(data, cursor); state["rules"][reg] = ("undefined" if op == 7 else "same", 0)
        elif op == 9:
            reg, cursor = read_leb(data, cursor); other, cursor = read_leb(data, cursor); state["rules"][reg] = ("register", other)
        elif op == 10: saved.append(copy.deepcopy(state))
        elif op == 11:
            require(saved, "CFI restore without saved state"); state = saved.pop()
        elif op in (12, 18):
            reg, cursor = read_leb(data, cursor); offset, cursor = read_leb(data, cursor, op == 18)
            state["cfa"] = (reg, offset * data_align if op == 18 else offset)
        elif op == 13:
            reg, cursor = read_leb(data, cursor); state["cfa"] = (reg, state["cfa"][1])
        elif op in (14, 19):
            offset, cursor = read_leb(data, cursor, op == 19); state["cfa"] = (state["cfa"][0], offset * data_align if op == 19 else offset)
        elif op == 0x2e:
            _, cursor = read_leb(data, cursor)  # GNU args size does not change CFA.
        else: raise ValueError(f"unsupported DW_CFA opcode {op:#x}")
        rows[pc] = copy.deepcopy(state)
    require(not saved, "unbalanced CFI remembered states")
    return rows


def dwarf_frames(elf, isa):
    abs64 = PROFILES[isa][4]
    frames = []
    for section in elf.sections:
        if section["name"] != ".eh_frame": continue
        data, cursor, cies = elf.section_data(section["index"]), 0, {}
        while cursor < len(data):
            start = cursor; require(cursor + 4 <= len(data), "truncated frame length")
            length = struct.unpack_from("<I", data, cursor)[0]; cursor += 4
            if not length:
                require(not any(data[cursor:]), "nonzero bytes after frame terminator"); break
            require(length != 0xffffffff and cursor + length <= len(data), "invalid DWARF32 frame extent")
            end, id_position = cursor + length, cursor
            identity = struct.unpack_from("<I", data, cursor)[0]; cursor += 4
            if identity == 0:
                require(data[cursor] in (1, 3), "unsupported CIE version"); version = data[cursor]; cursor += 1
                terminator = data.find(b"\0", cursor, end); require(terminator >= 0, "unterminated CIE augmentation")
                augmentation = data[cursor:terminator].decode(); cursor = terminator + 1
                code_align, cursor = read_leb(data, cursor, limit=end); data_align, cursor = read_leb(data, cursor, True, end)
                if version == 1: return_register = data[cursor]; cursor += 1
                else: return_register, cursor = read_leb(data, cursor, limit=end)
                require(augmentation.startswith("z"), "CIE must use bounded augmentation")
                count, cursor = read_leb(data, cursor, limit=end); augmentation_end = cursor + count
                require(augmentation_end <= end, "CIE augmentation exceeds record")
                personality, lsda_encoding, fde_encoding, fields = None, None, 0, {}
                for character in augmentation[1:]:
                    if character == "P":
                        fields["personality_encoding"] = cursor; require(data[cursor] == 0, "personality is not full64 absolute"); cursor += 1
                        relocation = elf.relocation(section["index"], cursor, abs64)
                        target = elf.symbols[relocation["symbol"]]
                        require(target["name"] == PERSONALITY and target["section"] == 0 and relocation["addend"] == 0, "wrong personality symbol")
                        require(cursor + 8 <= augmentation_end, "truncated full64 personality pointer")
                        personality = target["name"]; fields["personality_relocation"] = relocation; cursor += 8
                    elif character == "L": fields["lsda_encoding"] = cursor; lsda_encoding = data[cursor]; cursor += 1
                    elif character == "R": fde_encoding = data[cursor]; cursor += 1
                    else: raise ValueError("unexpected CIE augmentation field")
                require(cursor == augmentation_end, "CIE pointer widths do not match augmentation extent")
                require(lsda_encoding in (None, 0), "LSDA is not full64 absolute")
                require(fde_encoding == 0x1b, "expected PC-relative signed32 FDE code address")
                initial = {"cfa": (None, 0), "rules": {}}
                rows = cfi_rows(data[cursor:end], initial, code_align, data_align)
                cies[start] = {"personality": personality, "lsda_encoding": lsda_encoding, "fde_encoding": fde_encoding,
                               "code_align": code_align, "data_align": data_align, "return_register": return_register,
                               "initial": rows[max(rows)], "fields": fields}
            else:
                cie = cies.get(id_position - identity); require(cie is not None, "FDE points outside its CIE inventory")
                initial_position = cursor; location_reloc = elf.relocation(section["index"], cursor)
                require(location_reloc["kind"] in ({2} if isa == "x86_64" else {261} if isa == "aarch64" else {57}), "wrong FDE location relocation")
                code_section, code_offset = elf.resolve(location_reloc); cursor += 4
                size = struct.unpack_from("<I", data, cursor)[0]; range_position = cursor; cursor += 4
                count, cursor = read_leb(data, cursor, limit=end); augmentation_end = cursor + count
                require(augmentation_end <= end, "FDE augmentation exceeds record")
                lsda, lsda_relocation = None, None
                if cie["lsda_encoding"] is not None:
                    lsda_relocation = elf.relocation(section["index"], cursor, abs64)
                    lsda = elf.resolve(lsda_relocation); cursor += 8
                require(cursor == augmentation_end, "FDE LSDA pointer width is not eight bytes")
                rows = cfi_rows(data[cursor:end], cie["initial"], cie["code_align"], cie["data_align"], cie["initial"])
                require(max(rows) <= size, "CFI row exceeds owned function range")
                frames.append({"section": section["index"], "record": start, "code_section": code_section, "start": code_offset,
                               "size": size, "range_position": range_position, "initial_position": initial_position,
                               "cie": cie, "lsda": lsda, "lsda_relocation": lsda_relocation, "rows": rows,
                               "cfi_position": cursor, "cfi_end": end})
            cursor = end
    require(frames, "no owned FDEs")
    return frames


def decode_lsda(elf, isa, frame, expected_chain, known_typeinfos, expected_table_names, limit):
    section, start = frame["lsda"]
    data, cursor = elf.section_data(section), start
    require(cursor + 2 <= limit <= len(data) and data[cursor] == 255, "LSDA LPStart must be omitted")
    cursor += 1; type_encoding_position = cursor; type_encoding = data[cursor]; cursor += 1
    require(type_encoding in (0, 255), "type table must use full64 absolute encoding")
    ttype = None
    if type_encoding != 255:
        offset, cursor = read_leb(data, cursor, limit=limit); ttype = cursor + offset
        require(ttype <= limit and ttype % 8 == 0, "type table base outside aligned section")
    require(data[cursor] == 1, "call sites must use unsigned LEB fields"); cursor += 1
    size, cursor = read_leb(data, cursor, limit=limit); calls_end = cursor + size
    require(calls_end <= limit, "call-site table exceeds source table")
    calls = []
    while cursor < calls_end:
        positions, values = [], []
        for _ in range(4):
            positions.append(cursor); value, cursor = read_leb(data, cursor, limit=calls_end); values.append(value)
        begin, length, landing, action = values
        require(length > 0 and begin + length <= frame["size"], "call-site range outside source function")
        require(landing < frame["size"] and (landing or action == 0), "invalid no-pad call-site action")
        require(not calls or calls[-1]["begin"] + calls[-1]["length"] <= begin, "unordered/overlapping call sites")
        calls.append({"begin": begin, "length": length, "landing": landing, "action": action, "positions": positions})
    require(cursor == calls_end, "call-site byte count is not exact")
    abs64 = PROFILES[isa][4]
    visited_fields, type_slots, filters = [], {}, {}

    def typeinfo(index):
        require(ttype is not None and index > 0, "positive selector without type table")
        position = ttype - 8 * index
        require(position >= calls_end and position + 8 <= ttype, "type index outside reverse table")
        relocation = elf.relocations.get(section, {}).get(position)
        if relocation:
            require(relocation["kind"] == abs64 and relocation["addend"] == 0, "typeinfo is not an exact full64 symbol pointer")
            name = elf.symbols[relocation["symbol"]]["name"]
            require(name in known_typeinfos, "unexpected typeinfo symbol")
            type_slots[index] = {"position": position, "name": name, "relocation": relocation}
            return name
        require(data[position:position + 8] == b"\0" * 8, "null catch-all table slot must be encoded zero")
        type_slots[index] = {"position": position, "name": None}
        return None

    def chain(head):
        if not head: return [("cleanup", None)]
        position, seen, result = calls_end + head - 1, set(), []
        while True:
            require(position >= calls_end and (ttype is None or position < ttype), "action offset outside table")
            require(position not in seen, "cyclic action records"); seen.add(position)
            selector_position = position
            selector, second = read_leb(data, position, True, ttype)
            displacement, after = read_leb(data, second, True, ttype)
            visited_fields.append({"selector_position": selector_position, "selector": selector,
                                   "second_position": second, "after": after, "displacement": displacement})
            if selector > 0: result.append(("catch", typeinfo(selector)))
            elif selector == 0: result.append(("cleanup", None))
            else:
                require(ttype is not None, "filter without type table base")
                filter_position, items = ttype - selector - 1, []
                cursor_ = filter_position
                require(cursor_ >= ttype and cursor_ < limit, "filter byte offset outside source table")
                for _ in range(len(known_typeinfos) + 2):
                    index, cursor_ = read_leb(data, cursor_, limit=limit)
                    if not index: break
                    items.append(typeinfo(index))
                else: raise ValueError("unterminated exclusion filter")
                require(None not in items, "null typeinfo in exclusion filter")
                filters[filter_position] = {"selector": selector, "end": cursor_, "items": tuple(items)}
                result.append(("filter", tuple(items)))
            if not displacement: break
            position = second + displacement  # Address of SECOND field, not its end.
        return result

    unwind = [call for call in calls if call["landing"]]
    require(len(calls) == 4 and len(unwind) == 2 and len({call["landing"] for call in unwind}) == 2,
            "source ordinary/two-invoke/resume call-site inventory changed")
    for call in unwind:
        actual = chain(call["action"])
        require(actual == expected_chain, f"ordered catch/filter/cleanup meaning changed: {actual!r}")
    for call in calls:
        if not call["landing"]: require(call["action"] == 0, "ordinary call/resume gained handler")
    # Every registered named typeinfo, including the otherwise-unused typeid,
    # is checked. This does not assume the emitter's type-index assignment.
    require({typeinfo(index) for index in range(1, len(expected_table_names) + 1)} == expected_table_names,
            "whole source typeinfo/typeid inventory changed")
    require(set(offset for offset in elf.relocations.get(section, {}) if start <= offset < limit) ==
            {slot["position"] for slot in type_slots.values() if "relocation" in slot}, "unowned extra relocation in source LSDA")
    records = {field["selector_position"]: field for field in visited_fields}
    action_end = calls_end
    for position, field in sorted(records.items()):
        require(position == action_end, "unreferenced bytes inside source action records")
        action_end = field["after"]
    if ttype is not None:
        type_start = ttype - len(expected_table_names) * 8
        require(type_start == (action_end + 7) // 8 * 8 and not any(data[action_end:type_start]),
                "type table extent/alignment differs from full source inventory")
        tail = ttype
        for position, filter_ in sorted(filters.items()):
            require(position == tail, "unreferenced bytes inside source exclusion filters")
            tail = filter_["end"]
    else: tail = action_end
    require(not any(data[tail:limit]), "unowned trailing bytes in source LSDA")
    require(type_encoding != 255 or not type_slots and not filters, "omitted table contains selectors")
    require(all(field["after"] <= min([slot["position"] for slot in type_slots.values()] or [ttype or len(data)])
                for field in visited_fields), "action bytes overlap type table")
    return {"section": section, "offset": start, "type_base": ttype, "type_encoding_position": type_encoding_position,
            "calls": calls, "action_fields": visited_fields, "type_slots": type_slots, "filters": filters}


def disassembly(text):
    section, result = None, {}
    for line in text.splitlines():
        match = re.match(r"Disassembly of section (.+):", line)
        if match: section = match[1]; continue
        match = re.match(r"\s*([0-9a-fA-F]+):\s+(\S.*)", line)
        if match and section is not None:
            operation = re.sub(r"\s+", " ", match[2].split("//", 1)[0].strip().lower())
            result.setdefault(section, []).append((int(match[1], 16), operation))
    return result


def audit_object(data, isa, module, code):
    elf = Elf(data); require(elf.machine == PROFILES[isa][3], "wrong ELF machine")
    for section in elf.sections:
        if section["kind"] == 1 and section["size"]:
            require(section["name"] == ".eh_frame" or section["name"].startswith((".text", ".data", ".rodata", ".gcc_except_table")),
                    "unexpected nonempty PROGBITS outside declared source/derived object profile")
    definitions = {fn["name"]: fn for fn in module["functions"] if fn["entry"] is not None}
    symbols = {name: elf.named.get(name) for name in definitions}
    require(all(s is not None and s["section"] and s["size"] > 0 and s["info"] & 15 == 2 for s in symbols.values()), "complete source function inventory missing")
    for global_ in module["globals"]:
        require(global_["name"] in elf.named and elf.named[global_["name"]]["section"] != 0, "source global omitted")
        global_symbol = elf.named[global_["name"]]
        initializer = global_["initializer"]
        require(global_symbol["size"] == len(initializer["bytes"]), "source global extent changed")
        actual = elf.section_data(global_symbol["section"])[global_symbol["value"]:global_symbol["value"] + global_symbol["size"]]
        require(actual == bytes(initializer["bytes"]), "source initializer bytes changed")
        for expected in initializer["relocations"]:
            relocation = elf.relocation(global_symbol["section"], global_symbol["value"] + expected["offset"], PROFILES[isa][4])
            require(elf.symbols[relocation["symbol"]]["name"] == expected["symbol"] and relocation["addend"] == expected["addend"],
                    "source initializer relocation identity changed")
    for alias in module["aliases"]:
        source, target = elf.named[alias["name"]], elf.named[alias["aliasee"]]
        require((source["section"], source["value"], source["size"]) == (target["section"], target["value"], target["size"]), "source alias attachment changed")
    require(elf.named[PERSONALITY]["section"] == 0 and elf.named["_Unwind_Resume"]["section"] == 0, "provider requirements missing")
    frames = dwarf_frames(elf, isa)
    owned = {(s["section"], s["value"], s["size"]): name for name, s in symbols.items()}
    require(len(owned) == len(definitions) and len(frames) == len(definitions), "FDE source definition inventory differs")
    require({(f["code_section"], f["start"], f["size"]) for f in frames} == set(owned), "FDE range/owner is not exact")
    groups = {group["key"]: group for group in elf.groups()}
    require(set(groups) == {"eh_any_key", "eh_nodedup_key"} and groups["eh_any_key"]["flags"] == 1 and groups["eh_nodedup_key"]["flags"] == 0, "source COMDAT policy changed")
    results, cfi_checks, calls_checked = {}, 0, 0
    fp, sp, ra = PROFILES[isa][5:]
    for frame in frames:
        name = owned[(frame["code_section"], frame["start"], frame["size"])]; fn = definitions[name]
        require(frame["cie"]["return_register"] == ra, "wrong CIE return register")
        initial = frame["rows"][0]
        require(initial["cfa"] == (sp, 8 if isa == "x86_64" else 0), "wrong initial CFA")
        section_name = elf.sections[frame["code_section"]]["name"]
        instructions = [(pc - frame["start"], op) for pc, op in code.get(section_name, []) if frame["start"] <= pc < frame["start"] + frame["size"]]
        require(instructions and instructions[0][0] == 0, "function disassembly missing")
        if name not in EH_NAMES:
            require(frame["lsda"] is None and frame["cie"]["personality"] is None, "cold non-EH function gained exception contract")
            continue
        require(frame["cie"]["personality"] == PERSONALITY and frame["lsda"] is not None, "EH source personality/LSDA omitted")
        clauses, cleanup = source_clauses(name)
        expected_chain = clauses + ([("cleanup", None)] if cleanup else [])
        table_names = set()
        for kind, value in clauses:
            if kind == "catch": table_names.add(value)
            else: table_names.update(value)
        if name != "eh_cleanup": table_names.add(TYPEINFOS[129])
        lsda_section, lsda_start = frame["lsda"]
        lsda_limit = min([other["lsda"][1] for other in frames if other["lsda"] is not None and
                          other["lsda"][0] == lsda_section and other["lsda"][1] > lsda_start] or
                         [elf.sections[lsda_section]["size"]])
        table = decode_lsda(elf, isa, frame, expected_chain, {*TYPEINFOS, TYPE_ALIAS}, table_names, lsda_limit)
        # Match object table intervals to real instructions without emitter
        # labels. RV direct calls consist of AUIPC followed by JALR.
        for call in table["calls"]:
            inside = [(pc, op) for pc, op in instructions if call["begin"] <= pc < call["begin"] + call["length"]]
            is_call = lambda op: bool(re.match(r"(?:call|bl|blr|jal|jalr)\b", op))
            require(inside and sum(is_call(op) for _, op in inside) == 1, "call-site interval does not cover exactly one machine call")
            require(all(is_call(op) or isa == "riscv64" and op.startswith("auipc ") for _, op in inside), "call-site includes unrelated instructions")
            for position in (call["begin"], *([call["landing"]] if call["landing"] else [])):
                row = frame["rows"][max(pc for pc in frame["rows"] if pc <= position)]
                require(row["cfa"] == (fp, 16) and row["rules"].get(fp) == ("offset", -16) and row["rules"].get(ra) == ("offset", -8), "wrong unwind row during call or landing")
                cfi_checks += 1
            calls_checked += 1
        # Actual outgoing argument areas and page probes both change SP while
        # CFA remains rooted in FP. Check every non-epilogue body SP decrement.
        decrements = []
        for position, op in instructions:
            if position and re.match(r"sub rsp,|sub sp, sp,|addi sp, sp, -|add sp, sp,", op):
                row = frame["rows"][max(pc for pc in frame["rows"] if pc <= position)]
                require(row["cfa"] == (fp, 16), "stack allocation changed fixed-frame CFA")
                decrements.append(position); cfi_checks += 1
        require(len(decrements) >= 3, "large fixed frame/outgoing stack argument evidence missing")
        if fn.get("comdat"):
            group = groups[fn["comdat"]]
            require(frame["code_section"] in group["members"] and table["section"] in group["members"], "EH derived table detached from source group")
            require(elf.sections[table["section"]]["flags"] & 0x200, "EH derived section lacks SHF_GROUP")
            for relocation in elf.relocations.get(table["section"], {}).values():
                require(relocation["rela_section"] in group["members"], "EH type relocation detached from source group")
        results[name] = {"frame": frame, "lsda": table, "fixed_frame_sp_changes": decrements}
    require(len(results) == len(EH_NAMES), "EH function inventory not complete")
    return elf, {"functions": len(definitions), "eh_functions": len(results), "call_sites": calls_checked,
                 "cfi_row_checks": cfi_checks, "groups": groups, "details": results}


class EhObjectDecoderTests(unittest.TestCase):
    def test_standard_leb_and_action_field_origin(self):
        self.assertEqual(read_leb(bytes.fromhex("8001"), 0), (128, 2))
        self.assertEqual(read_leb(bytes.fromhex("827f"), 0, True), (-126, 2))
        # Ordered [130,1,0]: head five, next is based on the second field.
        data = bytes.fromhex("0000017d82017c")
        position, chain = 4, []
        while True:
            selector, second = read_leb(data, position, True)
            offset, _ = read_leb(data, second, True); chain.append(selector)
            if not offset: break
            position = second + offset
        self.assertEqual(chain, [130, 1, 0])
        for data_ in (b"\x80", b"\x80" * 11):
            with self.assertRaises(ValueError): read_leb(data_, 0)


class NativeEhObjectTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.compiler = Path(os.environ.get("OCOREC", str(ROOT / "target/debug/ocorec"))).resolve()
        cls.sdk = Path(os.environ.get("OCORE_TEST_LLVM22_BIN", str(SDK))).resolve()
        required = [cls.compiler, *[cls.sdk / name for name in ("clang", "llvm-as", "llvm-objdump", "llvm-readobj", "llvm-dwarfdump")]]
        missing = [str(path) for path in required if not path.is_file()]
        if missing:
            reason = "actual compiler and exact LLVM22 SDK required: " + ", ".join(missing)
            if os.environ.get("OCORE_TEST_REQUIRE_ALL_ISAS") == "1": raise RuntimeError(reason)
            raise unittest.SkipTest(reason)
        for path in required[1:]:
            result = subprocess.run([str(path), "--version"], capture_output=True, text=True, timeout=15)
            require(result.returncode == 0 and re.search(r"\b(?:clang version|LLVM version) 22\.1\.6\b", result.stdout), "exact LLVM22.1.6 required: " + str(path))

    def setUp(self):
        retained = os.environ.get("OCORE_TEST_NATIVE_EH_OBJECTS_OUTPUT_DIR")
        if retained:
            root = Path(retained).expanduser().resolve(); root.mkdir(parents=True, exist_ok=True)
            self.directory = Path(tempfile.mkdtemp(prefix="run-", dir=root))
        else:
            temporary = tempfile.TemporaryDirectory(prefix="ocore-native-eh-objects-")
            self.addCleanup(temporary.cleanup); self.directory = Path(temporary.name)
        self.sequence, self.artifacts = 0, [artifact(Path(__file__)), artifact(self.compiler)]

    def command(self, argv):
        argv = [str(item) for item in argv]
        result = subprocess.run(argv, cwd=ROOT, capture_output=True, timeout=120)
        path = self.directory / f"command-{self.sequence:03}.json"; self.sequence += 1
        path.write_text(json.dumps({"argv": argv, "cwd": str(ROOT), "exit_code": result.returncode,
                                    "stdout": result.stdout.decode(errors="replace"), "stderr": result.stderr.decode(errors="replace")}, indent=2) + "\n")
        self.artifacts.append(artifact(path))
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        return result

    def mutation_controls(self, original, isa, module, code, elf, audit, case="native-json"):
        """Mutate real admitted object metadata, retaining its ELF container."""
        details = audit["details"]; ordered = details["eh_ordered"]; frame, table = ordered["frame"], ordered["lsda"]
        mutations = []
        def change(label, file_offset, raw): mutations.append((label, file_offset, raw))
        abs32 = {"x86_64": 10, "aarch64": 258, "riscv64": 1}[isa]
        for label, relocation in (("personality-width", frame["cie"]["fields"]["personality_relocation"]), ("lsda-width", frame["lsda_relocation"]),
                                  ("typeinfo-width", next(slot["relocation"] for slot in table["type_slots"].values() if "relocation" in slot))):
            info = (relocation["symbol"] << 32) | abs32
            change(label, relocation["file_offset"] + 8, struct.pack("<Q", info))
        relocation = frame["cie"]["fields"]["personality_relocation"]
        change("personality-addend", relocation["file_offset"] + 16, struct.pack("<q", 8))
        section_offset = elf.sections[table["section"]]["offset"]
        null_slot = next(slot for slot in table["type_slots"].values() if slot["name"] is None)
        change("catchall-not-null", section_offset + null_slot["position"], struct.pack("<Q", 1))
        action = next(field for field in table["action_fields"] if field["displacement"] < 0)
        # Zero displacement removes the remainder of the ordered chain.
        change("ordered-action-truncated", section_offset + action["second_position"], b"\0")
        filter_ = next(item for item in table["filters"].values() if not item["items"])
        change("empty-filter-not-empty", section_offset + filter_["end"] - 1, b"\x01")
        change("type-encoding-narrow", section_offset + table["type_encoding_position"], b"\x03")
        change("callsite-empty-range", section_offset + table["calls"][0]["positions"][1], b"\0")
        change("fde-range-short", elf.sections[frame["section"]]["offset"] + frame["range_position"], struct.pack("<I", frame["size"] - 1))
        cfi_section = elf.sections[frame["section"]]
        fp = PROFILES[isa][5]
        cfi = elf.section_data(frame["section"])
        factor = frame["cie"]["data_align"]
        require(factor < 0 and -16 % factor == 0, "saved-FP offset not expressible using source CIE factor")
        encoded_offset = -16 // factor
        require(0 < encoded_offset < 128, "saved-FP mutation needs a single-byte standard ULEB")
        pattern = bytes([0x80 | fp, encoded_offset])
        position = cfi.find(pattern, frame["cfi_position"], frame["cfi_end"])
        require(position >= 0, "saved-FP DW_CFA mutation location missing")
        change("cfi-fp-save-wrong-offset", cfi_section["offset"] + position + 1, b"\x01")
        # Reattach a real grouped LSDA to the OTHER source group.
        any_table = details["eh_any"]["lsda"]; group = audit["groups"]["eh_any_key"]
        group_section = elf.sections[group["section"]]
        member_index = list(group["members"]).index(any_table["section"])
        change("group-table-detached", group_section["offset"] + 4 * (member_index + 1), struct.pack("<I", details["eh_nodedup"]["lsda"]["section"]))
        # Swap a valid LSDA relocation owner without changing its width.
        other = details["eh_catchall"]["frame"]["lsda_relocation"]
        relocation = frame["lsda_relocation"]
        change("lsda-owner-swapped", relocation["file_offset"] + 8,
               struct.pack("<Qq", (other["symbol"] << 32) | relocation["kind"], other["addend"]))
        # A group-signature section misrepresented as executable data must not
        # become an unowned, silently accepted PROGBITS contribution.
        change("unexpected-progbits", group_section["header"] + 4, struct.pack("<I", 1))
        controls = []
        for label, offset, raw in mutations:
            data = bytearray(original); data[offset:offset + len(raw)] = raw
            path = self.directory / f"{isa}-{case}-{label}.o"; path.write_bytes(data); self.artifacts.append(artifact(path))
            with self.assertRaises(ValueError, msg=label): audit_object(data, isa, module, code)
            controls.append({"label": label, "object": artifact(path), "rejected": True})
        return controls

    def test_static_full64_cfi_lsda_actions_filters_groups_and_object_mutants_all_three(self):
        compiler_before = artifact(self.compiler); records = []
        for isa, profile in PROFILES.items():
            with self.subTest(isa=isa):
                source = self.directory / f"{isa}-original.ll"; source.write_text(llvm_counterpart(isa))
                bitcode = source.with_suffix(".bc")
                self.command([self.sdk / "llvm-as", source, "-o", bitcode])
                self.artifacts += [artifact(source), artifact(bitcode)]
                module = fixture(isa, artifact(source)["sha256"])
                native = self.directory / f"{isa}-authored-native.json"; native.write_text(json.dumps(module, indent=2) + "\n")
                receipt = self.directory / f"{isa}-verification.json"
                self.command([self.compiler, native, "--input-kind", "native-ir", "--verify-native", "--receipt", receipt])
                self.assertEqual(json.loads(receipt.read_text())["module_sha256"], artifact(native)["sha256"])
                assembly = native.with_suffix(".s")
                self.command([self.compiler, native, "--input-kind", "native-ir", "--target", profile[0], "--emit", "asm", "-o", assembly])
                object_ = self.directory / f"{isa}-owned-sdk22.o"
                self.command([self.sdk / "clang", "-target", profile[1], *profile[2], "-c", assembly, "-o", object_])
                code_text = self.command([self.sdk / "llvm-objdump", "-d", "--no-show-raw-insn",
                                          *(["--x86-asm-syntax=intel"] if isa == "x86_64" else []), object_]).stdout.decode()
                self.command([self.sdk / "llvm-readobj", "--sections", "--symbols", "--relocations", "--section-groups", object_])
                self.command([self.sdk / "llvm-dwarfdump", "--eh-frame", object_])
                elf, audit = audit_object(object_.read_bytes(), isa, module, disassembly(code_text))
                controls = self.mutation_controls(object_.read_bytes(), isa, module, disassembly(code_text), elf, audit)
                self.artifacts += [artifact(native), artifact(receipt), artifact(assembly), artifact(object_)]
                records.append({"isa": isa, "native_module": artifact(native), "llvm_counterpart": artifact(source), "bitcode_counterpart": artifact(bitcode),
                                "object": artifact(object_), "inventory": {key: value for key, value in audit.items() if key != "details"},
                                "exception_tables": [{"function": name, "section": value["lsda"]["section"], "offset": value["lsda"]["offset"],
                                                      "type_base": value["lsda"]["type_base"], "call_sites": value["lsda"]["calls"],
                                                      "type_slots": list(value["lsda"]["type_slots"].values()), "filters": list(value["lsda"]["filters"].values()),
                                                      "ordered_source_clauses": source_clauses(name), "fixed_frame_sp_changes": value["fixed_frame_sp_changes"]}
                                                     for name, value in audit["details"].items()], "negative_controls": controls})
        self.assertEqual(compiler_before, artifact(self.compiler))
        for path in [self.sdk / name for name in ("clang", "llvm-as", "llvm-objdump", "llvm-readobj", "llvm-dwarfdump")]: self.artifacts.append(artifact(path))
        for binding in self.artifacts: self.assertEqual(binding, artifact(binding["path"]))
        report = {"schema": "ocore-native-eh-object-conformance-v1", "compiler": compiler_before, "test_source": artifact(Path(__file__)),
                  "fixture_kind": "source_authored_native_json_with_unimported_complete_llvm_counterpart", "object_structure_verified": True,
                  "machine_bytes_semantically_verified": False, "mutation_controls_scope": "metadata-only; original machine instruction bytes held fixed",
                  "native_exception_execution_verified": False, "source_import_verified": False, "dynamic_alloca_supported": False,
                  "dynamic_interposition_supported": False, "jit_publication_supported": False, "dependency_closure_complete": False,
                  "runtime_complete": False, "compiler_complete": False, "native_kernel_qualified": False, "targets": records, "artifacts": self.artifacts}
        output = self.directory / "eh-object-conformance.json"; output.write_text(json.dumps(report, indent=2) + "\n")
        print("EH object report:", output)

    def test_whole_unchanged_llvm_and_bitcode_import_owned_objects_all_three(self):
        """Real CLI import of complete originals; independent object structure."""
        compiler_before = artifact(self.compiler); records = []
        for isa, profile in PROFILES.items():
            source = self.directory / f"{isa}-original.ll"; source.write_text(llvm_counterpart(isa))
            bitcode = source.with_suffix(".bc")
            self.command([self.sdk / "llvm-as", source, "-o", bitcode])
            originals = {path: artifact(path) for path in (source, bitcode)}
            for input_ in (source, bitcode):
                with self.subTest(isa=isa, input_kind=input_.suffix):
                    prefix = self.directory / (isa + input_.suffix)
                    native = prefix.with_suffix(input_.suffix + ".native.json")
                    self.command([self.compiler, input_, "--input-kind", "llvm-ir", "--target", profile[0], "--emit", "mir", "-o", native])
                    module = json.loads(native.read_text())
                    self.assertEqual(module["provenance"]["input_sha256"], originals[input_]["sha256"])
                    self.assertEqual(module["provenance"]["source_function_count"], 12)
                    self.assertEqual(module["provenance"]["source_global_count"], 132)
                    self.assertEqual(module["provenance"]["source_alias_count"], 2)
                    self.assertEqual(module["provenance"]["referenced_comdat_count"], 2)
                    self.assertEqual({fn["name"] for fn in module["functions"]},
                                     {*EH_NAMES, "eh_cold", "eh_may_throw", PERSONALITY, "_Unwind_Resume", "llvm.eh.typeid.for.p0"})
                    self.assertEqual({global_["name"] for global_ in module["globals"]}, {*TYPEINFOS, "eh_cold_address", "eh_type_address"})
                    self.assertEqual({alias["name"] for alias in module["aliases"]}, {"eh_cold_alias", TYPE_ALIAS})
                    object_ = prefix.with_suffix(input_.suffix + ".own.o")
                    self.command([self.compiler, input_, "--input-kind", "llvm-ir", "--target", profile[0], "--emit", "obj", "--keep-asm", "-o", object_])
                    assembly = object_.with_suffix(".s")
                    self.assertTrue(assembly.is_file(), "actual object CLI must retain owned assembly")
                    code_text = self.command([self.sdk / "llvm-objdump", "-d", "--no-show-raw-insn",
                                              *(["--x86-asm-syntax=intel"] if isa == "x86_64" else []), object_]).stdout.decode()
                    self.command([self.sdk / "llvm-readobj", "--sections", "--symbols", "--relocations", "--section-groups", object_])
                    self.command([self.sdk / "llvm-dwarfdump", "--eh-frame", object_])
                    elf, audit = audit_object(object_.read_bytes(), isa, module, disassembly(code_text))
                    controls = self.mutation_controls(object_.read_bytes(), isa, module, disassembly(code_text), elf, audit, input_.suffix[1:])
                    self.artifacts += [artifact(input_), artifact(native), artifact(assembly), artifact(object_)]
                    records.append({"isa": isa, "input": originals[input_], "native_module": artifact(native), "object": artifact(object_),
                                    "inventory": {key: value for key, value in audit.items() if key != "details"}, "negative_controls": controls})
            for path, original in originals.items(): self.assertEqual(original, artifact(path))
        self.assertEqual(compiler_before, artifact(self.compiler))
        for path in [self.sdk / name for name in ("clang", "llvm-as", "llvm-objdump", "llvm-readobj", "llvm-dwarfdump")]: self.artifacts.append(artifact(path))
        assembler = os.environ.get("CLANG", "clang")
        import shutil
        assembler_path = shutil.which(assembler)
        if assembler_path:
            self.command([assembler_path, "--version"]); self.artifacts.append(artifact(assembler_path))
        for binding in self.artifacts: self.assertEqual(binding, artifact(binding["path"]))
        report = {"schema": "ocore-native-eh-llvm-object-conformance-v1", "compiler": compiler_before, "test_source": artifact(Path(__file__)),
                  "fixture_kind": "whole_source_authored_original_llvm_and_bitcode", "object_structure_verified": True, "source_import_verified": True,
                  "machine_bytes_semantically_verified": False, "mutation_controls_scope": "metadata-only; original machine instruction bytes held fixed",
                  "native_exception_execution_verified": False, "dynamic_alloca_supported": False, "dynamic_interposition_supported": False,
                  "jit_publication_supported": False, "dependency_closure_complete": False, "runtime_complete": False, "compiler_complete": False,
                  "native_kernel_qualified": False, "targets": records, "artifacts": self.artifacts}
        output = self.directory / "eh-llvm-object-conformance.json"; output.write_text(json.dumps(report, indent=2) + "\n")
        print("Whole LLVM EH object report:", output)


if __name__ == "__main__":
    unittest.main()
