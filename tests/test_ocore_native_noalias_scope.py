"""Whole LLVM noalias-scope compiler conformance, never a runtime substitute.

LLVM22's original LL/BC and Clang objects are retained unchanged. The native
profile records the complete scope graph but uses none of its alias promises
for optimization. Linux startup/syscalls only carry an independent scalar and
byte oracle. No external implementation, provider closure, kernel or silicon
qualification follows from these compiler regression fixtures.

OCORE_TEST_NOALIAS_REFERENCE_ONLY=1 runs the original Clang baseline without
invoking O-core. OCOREC selects the coherent private compiler for the own gate.
"""
import ctypes as C
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

from scripts import ocore_llvm_import as importer
from scripts.check_ocore_native_equivalence import TARGETS, elf
from tests import test_ocore_native_eh_objects as frames
from tests import test_ocore_native_weak as weak

MARKER = "llvm.experimental.noalias.scope.decl"
MASK = (1 << 64) - 1
SIZE = 96
DEFINITIONS = {"scope_empty", "scope_marker_only", "scope_identity_markers",
               "scope_graph_marker", "scope_wide_markers", "scope_loop",
               "scope_branch", "scope_cold_unused"}
EMPTY_BODIES = {"scope_empty", "scope_marker_only", "scope_identity_markers",
                "scope_graph_marker", "scope_wide_markers"}


def vectors():
    values = [0, 1, 2, 255, 256, 65535, 1 << 31, 1 << 32, 1 << 63,
              MASK, MASK - 1, 0x0123456789abcdef, 0xfedcba9876543210]
    state = 0x9e3779b97f4a7c15
    for _ in range(51):
        state ^= state << 13 & MASK
        state ^= state >> 7
        state ^= state << 17 & MASK
        values.append(state & MASK)
    lengths = (0, 1, 2, 3, 7, 15, 31, 32, 63, 64)
    return [(seed, lengths[index % len(lengths)], index & 1)
            for index, seed in enumerate(values)]


def expectation(seed, length, choice):
    a = [(seed + 3 * index) & 255 for index in range(SIZE)]
    b = [((seed >> 8) + 5 * index) & 255 for index in range(SIZE)]
    result = seed
    for index in range(length):
        a[index] = (a[index] + (seed & 255) + index) & 255
        b[index] ^= ((seed >> 8) + index) & 255
        result = ((result * 33 + a[index]) & MASK) ^ b[index]
    values = [result, result, *a, *b]
    tag = 23 if choice else 11
    branch = ((seed * 17 + tag) & MASK) ^ result
    a[0] = (seed + (3 if choice else 0)) & 255
    b[0] = ((seed >> 8) + (5 if choice else 0)) & 255
    return values + [branch, branch, *a, *b]


def golden():
    digest, checks = 0xcbf29ce484222325, 1
    digest = (digest ^ 0) * 0x100000001b3 & MASK
    for case in vectors():
        for value in expectation(*case):
            digest = (digest ^ value) * 0x100000001b3 & MASK
            checks += 1
    return f"OCORE-NOALIAS digest={digest:016x} checks={checks}\n".encode()


def llvm_body():
    # Each original scope has one declaration instruction except branch-common,
    # which has two mutually exclusive sites. The same loop declaration executes
    # per iteration; it is never hoisted or cloned by this native profile.
    text = r'''
@buffer_a = global [96 x i8] zeroinitializer, align 16
@buffer_b = global [96 x i8] zeroinitializer, align 16
@effect_log = global i64 0, align 8
@cold_marker = constant i64 707, align 8
declare void @llvm.experimental.noalias.scope.decl(metadata)
define void @scope_empty() { ret void }
define void @scope_marker_only() {
  tail call void @llvm.experimental.noalias.scope.decl(metadata !22)
  ret void
}
define void @scope_identity_markers() {
  call void @llvm.experimental.noalias.scope.decl(metadata !20)
  call void @llvm.experimental.noalias.scope.decl(metadata !21)
  ret void
}
define void @scope_graph_marker() {
  call void @llvm.experimental.noalias.scope.decl(metadata !23)
  ret void
}
define void @scope_wide_markers() {
'''
    for index in range(33):
        text += f"  call void @{MARKER}(metadata !{200 + index})\n"
    text += r'''  ret void
}
define i64 @scope_cold_unused() {
  call void @llvm.experimental.noalias.scope.decl(metadata !28)
  %cold = load volatile i64, ptr @cold_marker, align 8, !alias.scope !28
  ret i64 %cold
}
define i64 @scope_loop(i64 %seed, i64 %length) {
entry:
  %low = trunc i64 %seed to i8
  %high64 = lshr i64 %seed, 8
  %high = trunc i64 %high64 to i8
  br label %condition, !alias.scope !29
condition:
  %index = phi i64 [0, %entry], [%next, %work]
  %acc = phi i64 [%seed, %entry], [%mixed, %work]
  %done = icmp eq i64 %index, %length
  br i1 %done, label %exit, label %work
work:
  call void @llvm.experimental.noalias.scope.decl(metadata !24)
  call void @llvm.experimental.noalias.scope.decl(metadata !25)
  %index32 = trunc i64 %index to i32
  %pa = getelementptr [96 x i8], ptr @buffer_a, i64 0, i32 %index32, !alias.scope !24
  %pb = getelementptr [96 x i8], ptr @buffer_b, i64 0, i32 %index32, !noalias !24
  %old_a = load i8, ptr %pa, align 1, !alias.scope !24
  %old_b = load i8, ptr %pb, align 1, !noalias !24
  %index8 = trunc i64 %index to i8
  %biased_a = add i8 %old_a, %low
  %new_a = add i8 %biased_a, %index8
  %biased_b = add i8 %high, %index8
  %new_b = xor i8 %old_b, %biased_b
  store i8 %new_a, ptr %pa, align 1, !alias.scope !24
  store i8 %new_b, ptr %pb, align 1, !noalias !24
  %a64 = zext i8 %new_a to i64
  %b64 = zext i8 %new_b to i64
  %scaled = mul i64 %acc, 33
  %added = add i64 %scaled, %a64
  %mixed = xor i64 %added, %b64
  %next = add i64 %index, 1
  br label %condition, !noalias !29
exit:
  store volatile i64 %acc, ptr @effect_log, align 8
  ret i64 %acc
}
define i64 @scope_branch(i64 %seed, i64 %choice) {
entry:
  %pick = icmp ne i64 %choice, 0
  br i1 %pick, label %right, label %left
left:
  call void @llvm.experimental.noalias.scope.decl(metadata !26)
  %left_a = trunc i64 %seed to i8
  %left_high = lshr i64 %seed, 8
  %left_b = trunc i64 %left_high to i8
  store i8 %left_a, ptr @buffer_a, align 1, !alias.scope !26
  store i8 %left_b, ptr @buffer_b, align 1, !noalias !27
  %left_scaled = mul i64 %seed, 17
  %left_tagged = add i64 %left_scaled, 11
  %left_old = load volatile i64, ptr @effect_log, align 8
  %left_result = xor i64 %left_tagged, %left_old
  store volatile i64 %left_result, ptr @effect_log, align 8
  ret i64 %left_result
right:
  call void @llvm.experimental.noalias.scope.decl(metadata !27)
  %right_low = add i64 %seed, 3
  %right_a = trunc i64 %right_low to i8
  %right_high = lshr i64 %seed, 8
  %right_biased = add i64 %right_high, 5
  %right_b = trunc i64 %right_biased to i8
  store i8 %right_a, ptr @buffer_a, align 1, !alias.scope !27
  store i8 %right_b, ptr @buffer_b, align 1, !noalias !26
  %right_scaled = mul i64 %seed, 17
  %right_tagged = add i64 %right_scaled, 23
  %right_old = load volatile i64, ptr @effect_log, align 8
  %right_result = xor i64 %right_tagged, %right_old
  store volatile i64 %right_result, ptr @effect_log, align 8
  ret i64 %right_result
}
!0 = distinct !{!0, !"domain\00\FF"}
!1 = !{!"portable-domain\00\FE"}
!2 = distinct !{!2, !""}
!3 = distinct !{!3, !"cold-domain\00\FE"}
!10 = distinct !{!10, !0, !"twin"}
!11 = distinct !{!11, !0, !"twin"}
!12 = !{!"portable-scope\00\FD", !1}
!13 = distinct !{!13, !2, !""}
!14 = distinct !{!14, !0, !"loop-a"}
!15 = distinct !{!15, !0, !"loop-b"}
!16 = distinct !{!16, !0, !"branch-common"}
!17 = distinct !{!17, !3, !"cold-scope\00\FF"}
!20 = distinct !{!10}
!21 = distinct !{!11}
!22 = !{!12}
!23 = distinct !{!13}
!24 = !{!14}
!25 = !{!15}
!26 = distinct !{!16}
!27 = distinct !{!16}
!28 = !{!17}
!29 = !{!14, !15, !14}
'''
    for index in range(33):
        text += f'!{100 + index} = distinct !{{!{100 + index}, !0, !"wide-{index:02}"}}\n'
        text += f'!{200 + index} = distinct !{{!{100 + index}}}\n'
    return text


def carrier():
    # This existing freestanding startup only transports independent test data;
    # it supplies no noalias scope implementation or other external provider.
    syscall = weak.LINUX_CARRIER.split("static u64 syscall3", 1)[1].split("static u64 signed_bits", 1)[0]
    startup = weak.LINUX_CARRIER.split('#if defined(__x86_64__)\n__asm__', 1)[1]
    text = "typedef unsigned long long u64;\nstatic u64 syscall3" + syscall
    rows = ",\n".join("{" + f"0x{seed:016x}ULL,{length},{choice}" + "}" for seed, length, choice in vectors())
    text += "\nstatic const u64 cases[][3]={" + rows + "};\n"
    text += r'''
extern unsigned char buffer_a[96], buffer_b[96];
extern u64 effect_log;
extern u64 scope_loop(u64,u64),scope_branch(u64,u64);
extern void scope_empty(void),scope_marker_only(void),scope_identity_markers(void),scope_graph_marker(void),scope_wide_markers(void);
static u64 digest=0xcbf29ce484222325ULL,checks;
static int add(u64 actual,u64 expected) {
#ifdef CORRUPT_ORACLE
  expected^=1;
#endif
  if(actual!=expected)return 31;
  digest=(digest^actual)*0x100000001b3ULL;++checks;return 0;
}
int conformance_main(void) {
  scope_empty();scope_marker_only();scope_identity_markers();scope_graph_marker();scope_wide_markers();
  if(add(effect_log,0))return 31;
  for(u64 n=0;n<sizeof(cases)/sizeof(cases[0]);++n) {
    u64 seed=cases[n][0],length=cases[n][1],choice=cases[n][2],acc=seed;
    unsigned char a[96],b[96];
    for(u64 i=0;i<96;++i) {
      a[i]=(unsigned char)(seed+3*i);b[i]=(unsigned char)((seed>>8)+5*i);
      buffer_a[i]=a[i];buffer_b[i]=b[i];
    }
    for(u64 i=0;i<length;++i) {
      a[i]=(unsigned char)(a[i]+(unsigned char)seed+i);
      b[i]^=(unsigned char)((seed>>8)+i);
      acc=(33*acc+a[i])^b[i];
    }
    if(add(scope_loop(seed,length),acc)||add(effect_log,acc))return 31;
    for(u64 i=0;i<96;++i)if(add(buffer_a[i],a[i]))return 31;
    for(u64 i=0;i<96;++i)if(add(buffer_b[i],b[i]))return 31;
    u64 branch=(17*seed+(choice?23:11))^acc;
    a[0]=(unsigned char)(seed+(choice?3:0));b[0]=(unsigned char)((seed>>8)+(choice?5:0));
    if(add(scope_branch(seed,choice),branch)||add(effect_log,branch))return 31;
    for(u64 i=0;i<96;++i)if(add(buffer_a[i],a[i]))return 31;
    for(u64 i=0;i<96;++i)if(add(buffer_b[i],b[i]))return 31;
  }
'''
    output = golden().decode().rstrip()
    text += f"  if(checks!={1 + len(vectors()) * 388})return 37;\n"
    text += '  static char output[]="' + output.replace(output.split("digest=", 1)[1][:16], "0" * 16) + '\\n";\n'
    prefix = output.index("digest=") + len("digest=")
    text += f"  for(u64 i=0;i<16;++i){{u64 v=(digest>>(60-4*i))&15;output[{prefix}+i]=(char)(v<10?'0'+v:'a'+v-10);}}\n"
    text += r'''
#if defined(__x86_64__)
  if(syscall3(1,1,(u64)output,sizeof(output)-1)!=sizeof(output)-1)return 99;
#else
  if(syscall3(64,1,(u64)output,sizeof(output)-1)!=sizeof(output)-1)return 99;
#endif
  return 0;
}
#if defined(__x86_64__)
__asm__''' + startup
    return text


class NativeNoAliasExecutionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.environ.get("OCORE_TEST_NOALIAS_REFERENCE_ONLY") != "1":
            return weak.WeakNativeTests.setUpClass.__func__(cls)
        # Reference preparation must not depend on an existing O-core binary.
        cls.compiler = Path(os.environ.get("OCOREC", str(weak.ROOT/"target/debug/ocorec"))).resolve()
        cls.sdk = Path(os.environ.get("OCORE_TEST_LLVM22_BIN", str(weak.SDK))).resolve()
        cls.linker = shutil.which(os.environ.get("LD_LLD", "ld.lld"))
        cls.assembler = shutil.which("clang")
        tools = [cls.sdk/name for name in ("clang", "llvm-as", "llvm-nm", "llvm-readobj")]
        missing = [str(path) for path in tools if not path.is_file()]
        if cls.linker is None: missing.append("LD_LLD/ld.lld")
        if cls.assembler is None: missing.append("clang assembler from PATH")
        if missing:
            reason = "original reference requires exact LLVM22 SDK: " + ", ".join(missing)
            if os.environ.get("OCORE_TEST_REQUIRE_ALL_ISAS") == "1": raise RuntimeError(reason)
            raise unittest.SkipTest(reason)
        for path in tools:
            result = subprocess.run([str(path), "--version"], capture_output=True, text=True, timeout=15)
            if result.returncode or not re.search(r"\b(?:clang version|LLVM version|LLD) 22\.1\.6\b", result.stdout):
                raise RuntimeError("exact LLVM22.1.6 required: " + str(path))
    command = weak.WeakNativeTests.command

    def setUp(self):
        retained = os.environ.get("OCORE_TEST_NATIVE_NOALIAS_OUTPUT_DIR")
        if retained:
            base = Path(retained).expanduser().resolve(); base.mkdir(parents=True, exist_ok=True)
            self.directory = Path(tempfile.mkdtemp(prefix="run-", dir=base))
        else:
            temporary = tempfile.TemporaryDirectory(prefix="ocore-native-noalias-")
            self.addCleanup(temporary.cleanup); self.directory = Path(temporary.name)
        self.sequence, self.bound = 0, {}
        self.library = importer.LLVM(importer.discover_library(), importer.PINNED_SHA256)

    def bind(self, path):
        record = weak.artifact(path)
        previous = self.bound.setdefault(record["path"], record)
        self.assertEqual(previous, record, "original input, tool, source or output changed during execution")
        return record

    def original_sites(self, source):
        """Read LLVM instruction ordinals, not the importer's rewritten indices."""
        a, context = self.library, self.library.ContextCreate()
        module, error, message, buffer = importer.P(), importer.P(), importer.P(), None
        rows, inventory = [], {"functions": [], "definitions": [], "globals": [], "blocks": []}
        nodes = {}

        def md_bytes(metadata):
            self.assertTrue(metadata); self.assertEqual(a.GetMetadataKind(metadata), 0)
            value, length = a.MetadataAsValue(context, metadata), importer.U()
            pointer = a.GetMDString(value, C.byref(length))
            self.assertTrue(pointer or not length.value)
            return list(C.string_at(pointer, length.value)) if length.value else []

        def graph_node(metadata, role):
            """Read actual original CAPI identities; printer labels are evidence only."""
            self.assertTrue(metadata); self.assertEqual(a.GetMetadataKind(metadata), 4)
            if metadata in nodes:
                self.assertEqual(nodes[metadata]["role"], role)
                return nodes[metadata]["id"]
            value = a.MetadataAsValue(context, metadata)
            self.assertEqual(a.ValueAsMetadata(value), metadata)
            count = a.GetMDNodeNumOperands(value); values = (importer.P * count)()
            a.GetMDNodeOperands(value, values)
            operands = [a.ValueAsMetadata(part) if part else None for part in values]
            printed = a.PrintValueToString(value)
            self.assertTrue(printed)
            try: raw = C.string_at(printed)
            finally: a.DisposeMessage(printed)
            body = raw.partition(b" = ")[2]
            self.assertTrue(body.startswith((b"distinct !{", b"!{")))
            node = {"id": len(nodes), "role": role, "storage": "distinct" if body.startswith(b"distinct !{") else "uniqued",
                    "metadata_kind": 4, "printer_bytes": list(raw), "printer_sha256": hashlib.sha256(raw).hexdigest()}
            nodes[metadata] = node
            if role == "list":
                node["scopes"] = [graph_node(part, "scope") for part in operands]
            else:
                self.assertIn(len(operands), {1, 2} if role == "domain" else {2, 3})
                node["identity"] = ({"kind": "self_reference"} if operands[0] == metadata else
                                    {"kind": "bytes", "bytes": md_bytes(operands[0])})
                if role == "scope": node["domain"] = graph_node(operands[1], "domain")
                index = 1 if role == "domain" else 2
                node["description"] = md_bytes(operands[index]) if len(operands) > index else None
            return node["id"]

        # The complete fixture uses these scalar LLVM operations. Its two GEPs
        # require signed i32 index widening and byte-offset addition; all other
        # nonterminators have exactly one native operation. Unexpected source
        # operations require an explicit new contract, never a guessed span.
        expected_ops = {1: [], 2: [], 8: [{"op": "binary", "kind": "add"}],
                        12: [{"op": "binary", "kind": "mul"}], 21: [{"op": "binary", "kind": "l_shr"}],
                        25: [{"op": "binary", "kind": "xor"}], 27: [{"op": "load"}], 28: [{"op": "store"}],
                        29: [{"op": "cast", "kind": "s_ext"}, {"op": "binary", "kind": "add"}, {"op": "gep"}],
                        30: [{"op": "cast", "kind": "trunc"}], 31: [{"op": "cast", "kind": "z_ext"}],
                        42: [{"op": "i_cmp"}], 44: [{"op": "phi"}], 45: [{"op": "no_alias_scope_decl"}]}
        try:
            data = source.read_bytes()
            buffer = a.CreateMemoryBufferWithMemoryRangeCopy(data, len(data), b"noalias-original-instruction-inventory")
            self.assertEqual(a.ParseIRInContext2(context, buffer, C.byref(module), C.byref(error)), 0,
                             C.string_at(error).decode(errors="replace") if error else "original LLVM parse failed")
            self.assertEqual(a.VerifyModule(module, 2, C.byref(message)), 0,
                             C.string_at(message).decode(errors="replace") if message else "original LLVM verifier failed")
            kinds = {a.GetMDKindIDInContext(context, name, len(name)): name.decode() for name in (b"alias.scope", b"noalias")}
            for function in a.sequence(a.GetFirstFunction, a.GetNextFunction, module):
                name = a.name(function); inventory["functions"].append(name)
                blocks = list(a.sequence(a.GetFirstBasicBlock, a.GetNextBasicBlock, function))
                if blocks: inventory["definitions"].append(name)
                for block_id, block in enumerate(blocks):
                    native_ops = []
                    for ordinal, instruction in enumerate(a.sequence(a.GetFirstInstruction, a.GetNextInstruction, block)):
                        opcode = a.GetInstructionOpcode(instruction)
                        self.assertIn(opcode, expected_ops)
                        start, operations = len(native_ops), expected_ops[opcode]
                        native_ops.extend(operations)
                        count, attached = importer.S(), {}
                        entries = a.InstructionGetAllMetadataOtherThanDebugLoc(instruction, C.byref(count))
                        try:
                            for index in range(count.value):
                                kind = a.ValueMetadataEntriesGetKind(entries, index)
                                if kind in kinds:
                                    attached[kinds[kind]] = graph_node(a.ValueMetadataEntriesGetMetadata(entries, index), "list")
                        finally:
                            if entries: a.DisposeValueMetadataEntries(entries)
                        marker = opcode == 45 and a.name(a.GetCalledValue(instruction)) == MARKER
                        if opcode == 45: self.assertTrue(marker, "fixture calls must be exact owned markers")
                        marker_list = None
                        if marker:
                            self.assertTrue(a.IsAFunction(a.GetCalledValue(instruction)))
                            self.assertTrue(a.GetIntrinsicID(a.GetCalledValue(instruction)))
                            self.assertEqual(a.GetNumArgOperands(instruction), 1)
                            argument = a.GetOperand(instruction, 0)
                            self.assertEqual(a.GetTypeKind(a.TypeOf(argument)), 14)
                            marker_list = graph_node(a.ValueAsMetadata(argument), "list")
                        if marker or attached:
                            rows.append({"function": name, "block": block_id, "source_instruction": ordinal,
                                         "marker": marker, "scope_list": marker_list,
                                         "attachments": sorted(attached), "attachment_lists": attached,
                                         "opcode": opcode, "instruction": start, "instruction_count": len(operations),
                                         "expected_operations": operations})
                    inventory["blocks"].append({"function": name, "block": block_id, "expected_operations": native_ops})
            inventory["globals"] = [a.name(g) for g in a.sequence(a.GetFirstGlobal, a.GetNextGlobal, module)]
            self.assertEqual(set(inventory["definitions"]), DEFINITIONS)
            self.assertEqual(len(inventory["functions"]), 9)
            self.assertEqual(len(inventory["globals"]), 4)
            self.assertEqual(sum(row["marker"] for row in rows), 42)
            inventory["noalias_graph"] = sorted(nodes.values(), key=lambda row: row["id"])
            self.assertEqual(len(nodes), 88)
            return inventory, rows
        finally:
            if error: a.DisposeMessage(error)
            if message: a.DisposeMessage(message)
            if module: a.DisposeModule(module)
            if buffer: a.DisposeMemoryBuffer(buffer)
            a.ContextDispose(context)

    def check_graph(self, module, source_sites, inventory):
        graph = module["noalias_metadata"]
        domains, scopes, lists = ({row["id"]: row for row in graph[key]} for key in ("domains", "scopes", "lists"))
        self.assertEqual((len(domains), len(scopes), len(lists)), (4, 41, 43))
        self.assertEqual(len(set(domains) | set(scopes) | set(lists)), 88)
        evidence = module["provenance"]["noalias_metadata_source"]
        self.assertEqual(len(evidence), 88)
        self.assertEqual({row["id"] for row in evidence}, set(domains) | set(scopes) | set(lists))
        nodes = {**domains, **scopes, **lists}
        originals = {row["id"]: row for row in inventory["noalias_graph"]}
        roles = {identity: role for role, table in (("domain", domains), ("scope", scopes), ("list", lists))
                 for identity in table}
        mapped, reverse = {}, {}

        def compare_node(original_id, native_id):
            # LLVM CAPI handles only establish identity within the original
            # parse. Compare one consistent bijection anchored at every source
            # site; private numbering, descriptions and printer slots are not
            # identity. Ordered/repeated list members must retain exact edges.
            self.assertIn(original_id, originals); self.assertIn(native_id, nodes)
            if original_id in mapped:
                self.assertEqual(mapped[original_id], native_id, "original metadata identity changed at a source site")
                return
            self.assertNotIn(native_id, reverse, "distinct original metadata identities were coalesced")
            mapped[original_id], reverse[native_id] = native_id, original_id
            original, native = originals[original_id], nodes[native_id]
            self.assertEqual(original["role"], roles[native_id], "original metadata graph role changed")
            self.assertEqual(original["storage"], native["storage"], "original metadata storage changed")
            if original["role"] == "list":
                self.assertEqual(len(original["scopes"]), len(native["scopes"]), "original scope-list arity changed")
                for source_child, native_child in zip(original["scopes"], native["scopes"]):
                    compare_node(source_child, native_child)
            else:
                self.assertEqual(original["identity"], native["identity"], "original scope/domain identity bytes changed")
                self.assertEqual(original["description"], native["description"], "original scope/domain description bytes changed")
                if original["role"] == "scope": compare_node(original["domain"], native["domain"])

        for row in evidence:
            self.assertEqual(row["metadata_kind"], 4, "original MDTuple kind must be attested, never assumed")
            original_bytes = bytes(row["printer_bytes"])
            self.assertEqual(row["printer_sha256"], hashlib.sha256(original_bytes).hexdigest())
            # Display slots/process-address fallbacks attest storage only; the
            # typed module-local IDs and edges above remain the graph identity.
            prefix = b"distinct !{" if nodes[row["id"]]["storage"] == "distinct" else b"!{"
            self.assertTrue(original_bytes.split(b" = ", 1)[1].startswith(prefix))
        binary = next(row for row in domains.values() if row["description"] == list(b"domain\0\xff"))
        self.assertEqual(binary["identity"], {"kind": "self_reference"}); self.assertEqual(binary["storage"], "distinct")
        portable = next(row for row in domains.values() if row["identity"] == {"kind": "bytes", "bytes": list(b"portable-domain\0\xfe")})
        self.assertIsNone(portable["description"]); self.assertEqual(portable["storage"], "uniqued")
        twins = [row for row in scopes.values() if row["description"] == list(b"twin")]
        self.assertEqual(len(twins), 2); self.assertNotEqual(twins[0]["id"], twins[1]["id"])
        self.assertTrue(all(row["domain"] == binary["id"] and row["storage"] == "distinct"
                            and row["identity"] == {"kind": "self_reference"} for row in twins))
        text_scope = next(row for row in scopes.values() if row["identity"] == {"kind": "bytes", "bytes": list(b"portable-scope\0\xfd")})
        self.assertEqual(text_scope["domain"], portable["id"]); self.assertIsNone(text_scope["description"])
        self.assertEqual(text_scope["storage"], "uniqued")
        self.assertEqual(sum(row["description"] == [] for row in domains.values()), 1)
        self.assertEqual(sum(row["description"] == [] for row in scopes.values()), 1)
        cold = next(row for row in scopes.values() if row["description"] == list(b"cold-scope\0\xff"))
        self.assertEqual(domains[cold["domain"]]["description"], list(b"cold-domain\0\xfe"))
        branch = next(row["id"] for row in scopes.values() if row["description"] == list(b"branch-common"))
        wrappers = [row for row in lists.values() if row["scopes"] == [branch]]
        self.assertEqual(len(wrappers), 2); self.assertTrue(all(row["storage"] == "distinct" for row in wrappers))
        a, b = (next(row["id"] for row in scopes.values() if row["description"] == list(name)) for name in (b"loop-a", b"loop-b"))
        self.assertEqual(sum(row["scopes"] == [a, b, a] for row in lists.values()), 1)
        self.assertEqual(sum(bytes(row["description"] or []).startswith(b"wide-") for row in scopes.values()), 33)
        functions = {row["name"]: row for row in module["functions"]}
        declaration = functions[MARKER]
        self.assertIsNone(declaration["entry"]); self.assertEqual(declaration["blocks"], [])
        self.assertEqual(declaration["intrinsic"], MARKER)
        signature = declaration["signature"]
        self.assertEqual(module["types"][signature["result"]]["kind"], "void")
        self.assertEqual(len(signature["params"]), 1)
        self.assertEqual(module["types"][signature["params"][0]]["kind"], "metadata")
        for name, function in functions.items():
            expected_blocks = [row["block"] for row in inventory["blocks"] if row["function"] == name]
            self.assertEqual([row["id"] for row in function["blocks"]], expected_blocks,
                             "whole original function block inventory changed")
        for original_block in inventory["blocks"]:
            block = next(row for row in functions[original_block["function"]]["blocks"] if row["id"] == original_block["block"])
            self.assertEqual(len(block["instructions"]), len(original_block["expected_operations"]),
                             "whole original block's native instruction inventory changed")
            for instruction, expected_operation in zip(block["instructions"], original_block["expected_operations"]):
                for key, value in expected_operation.items():
                    self.assertEqual(instruction["operation"][key], value, "whole original instruction operation changed")
        retained = []
        source_markers = {(row["function"], row["block"], row["source_instruction"]): row
                          for row in source_sites if row["marker"]}
        for function in module["functions"]:
            for block in function["blocks"]:
                for instruction_index, instruction in enumerate(block["instructions"]):
                    operation = instruction["operation"]
                    if operation["op"] == "no_alias_scope_decl":
                        self.assertIsNone(instruction["result"])
                        self.assertEqual(len(lists[operation["scope_list"]]["scopes"]), 1)
                        key = (function["name"], block["id"], operation["source_instruction"])
                        self.assertIn(key, source_markers)
                        self.assertEqual(instruction_index, source_markers[key]["instruction"], "original declaration native position changed")
                        compare_node(source_markers[key]["scope_list"], operation["scope_list"])
                        retained.append(key)
        expected = [(row["function"], row["block"], row["source_instruction"]) for row in source_sites if row["marker"]]
        self.assertEqual(sorted(retained), sorted(expected))
        actual_sites = {(row["site"]["function"], row["site"]["block"], row["site"]["source_instruction"]): row
                        for row in graph["attachments"]}
        expected_sites = {(row["function"], row["block"], row["source_instruction"]): row
                          for row in source_sites if row["attachments"]}
        self.assertEqual(set(actual_sites), set(expected_sites))
        expanded, zero = 0, 0
        for key, attached in actual_sites.items():
            source = expected_sites[key]
            self.assertEqual(sorted(name for name in ("alias.scope", "noalias")
                                    if attached["alias_scope" if name == "alias.scope" else name] is not None), source["attachments"])
            site = attached["site"]; block = next(b for b in functions[site["function"]]["blocks"] if b["id"] == site["block"])
            self.assertEqual((site["instruction"], site["instruction_count"]),
                             (source["instruction"], source["instruction_count"]), "original attachment native range changed")
            for kind, original_list in source["attachment_lists"].items():
                compare_node(original_list, attached["alias_scope" if kind == "alias.scope" else kind])
            self.assertLessEqual(site["instruction"] + site["instruction_count"], len(block["instructions"]))
            if source["opcode"] == 29:
                self.assertEqual(site["instruction_count"], 3, "one GEP produces signed index extension, offset add and address")
                self.assertEqual([x["operation"]["op"] for x in block["instructions"][site["instruction"]:site["instruction"]+3]], ["cast", "binary", "gep"])
                expanded += 1
            if source["opcode"] == 2:
                self.assertEqual(site["instruction_count"], 0); zero += 1
                self.assertEqual(site["instruction"], len(block["instructions"]))
        self.assertEqual((expanded, zero), (2, 2))
        self.assertEqual(set(mapped), set(originals), "all original metadata nodes must be preserved")
        self.assertEqual(set(reverse), set(nodes), "native metadata graph must have exactly original source ownership")
        return {"domains": len(domains), "scopes": len(scopes), "lists": len(lists),
                "declarations": len(retained), "attachments": len(actual_sites),
                "one_to_many_source_sites": expanded, "zero_length_terminator_sites": zero,
                "full_original_node_printer_evidence": len(evidence), "source_graph_bijection_nodes": len(mapped),
                "exact_source_attachment_ranges": len(actual_sites)}

    def source_preservation_controls(self, original, module, source_sites, inventory):
        """Check the independent source oracle, not authored-graph admission.

        These alternative graphs need not violate NativeIR invariants. The
        independently inspected original source sites must still reject them.
        """
        invalid = json.loads(json.dumps(module)); graph = invalid["noalias_metadata"]
        loop_b = next(row["id"] for row in graph["scopes"] if row["description"] == list(b"loop-b"))
        loop_b_list = next(row["id"] for row in graph["lists"] if row["scopes"] == [loop_b])
        load = next(row for row in graph["attachments"] if row["site"]["function"] == "scope_loop"
                    and row["site"]["block"] == 2 and row["site"]["source_instruction"] == 5)
        load["alias_scope"] = loop_b_list
        cases = [("valid_scope_list_reassignment_loses_original_identity", invalid, "original metadata identity changed at a source site")]
        invalid = json.loads(json.dumps(module))
        store = next(row for row in invalid["noalias_metadata"]["attachments"] if row["site"]["function"] == "scope_loop"
                     and row["site"]["block"] == 2 and row["site"]["source_instruction"] == 12)
        store["site"]["instruction"] -= 1
        cases.append(("valid_range_reassignment_loses_original_store", invalid, "original attachment native range changed"))
        controls = []
        for name, value, diagnostic in cases:
            path = original.with_name(original.name+".source-oracle-"+name+".json")
            path.write_text(json.dumps(value, indent=2)+"\n")
            with self.assertRaisesRegex(AssertionError, diagnostic): self.check_graph(value, source_sites, inventory)
            controls.append({"case": name, "input": self.bind(path), "rejected_by_independent_source_oracle": True,
                             "production_admission_rejection_claimed": False, "expected_diagnostic": diagnostic})
        return controls

    def admission_controls(self, original, module):
        """Schema-valid authored mutations must reach their specific guard.

        A valid alternative graph is not claimed cryptographically forged here:
        these checks test invariant violations and retained source storage/digest
        evidence. Full source provenance is independently checked on originals.
        """
        def clone(): return json.loads(json.dumps(module))
        def function(value, name): return next(row for row in value["functions"] if row["name"] == name)
        def declarations(value, name):
            return [instruction for block in function(value, name)["blocks"] for instruction in block["instructions"]
                    if instruction["operation"]["op"] == "no_alias_scope_decl"]
        def list_node(value, identity):
            return next(row for row in value["noalias_metadata"]["lists"] if row["id"] == identity)
        cases = []
        def case(name, value, diagnostic): cases.append((name, value, diagnostic))

        invalid = clone(); ops = declarations(invalid, "scope_identity_markers")
        list_node(invalid, ops[1]["operation"]["scope_list"])["scopes"] = list_node(invalid, ops[0]["operation"]["scope_list"])["scopes"][:]
        case("same_scope_different_distinct_wrappers", invalid, "dominates another declaration of the same actual scope")
        invalid = clone(); ops = declarations(invalid, "scope_wide_markers")
        actual = list_node(invalid, ops[0]["operation"]["scope_list"])["scopes"][:]
        for op in ops[1:]: list_node(invalid, op["operation"]["scope_list"])["scopes"] = actual[:]
        case("all_33_declarations_same_actual_scope", invalid, "dominates another declaration of the same actual scope")
        invalid = clone(); branch = function(invalid, "scope_branch")
        entry, left, right = branch["blocks"]
        # Source block order is entry, left, right. These SSA-independent paths
        # now force the first declaration to dominate the second across blocks.
        entry["terminator"] = {"op": "jump", "target": left["id"]}
        left["terminator"] = {"op": "jump", "target": right["id"]}
        case("cross_block_scope_dominance", invalid, "dominates another declaration of the same actual scope")
        invalid = clone(); cold = function(invalid, "scope_cold_unused")["blocks"][0]
        extra = json.loads(json.dumps(declarations(invalid, "scope_cold_unused")[0]))
        extra["operation"]["source_instruction"] = 2; cold["instructions"].append(extra)
        case("cold_unexecuted_function_dominance", invalid, "dominates another declaration of the same actual scope")
        invalid = clone(); ops = declarations(invalid, "scope_identity_markers")
        ops[1]["operation"]["source_instruction"] = ops[0]["operation"]["source_instruction"]
        case("duplicate_original_marker_ordinal", invalid, "duplicate marker source instruction")
        invalid = clone(); graph = invalid["noalias_metadata"]
        graph["scopes"][1]["id"] = graph["scopes"][0]["id"]
        case("duplicate_node_identity", invalid, "duplicate node ID across metadata tables")
        invalid = clone(); next(row for row in invalid["noalias_metadata"]["scopes"]
                                if row["description"] == list(b"cold-scope\0\xff"))["domain"] = 999999
        case("cold_unknown_domain", invalid, "scope references an unknown domain")
        invalid = clone(); list_node(invalid, declarations(invalid, "scope_marker_only")[0]["operation"]["scope_list"])["scopes"] = [invalid["noalias_metadata"]["domains"][0]["id"]]
        case("domain_used_as_scope", invalid, "scope list references an unknown scope")
        invalid = clone(); node = list_node(invalid, declarations(invalid, "scope_marker_only")[0]["operation"]["scope_list"])
        node["scopes"] *= 2
        case("declaration_two_scopes", invalid, "declaration requires exactly one actual scope")
        invalid = clone(); declarations(invalid, "scope_marker_only")[0]["operation"]["scope_list"] = 999999
        case("unknown_declaration_list", invalid, "declaration references an unknown scope list")
        invalid = clone(); node = declarations(invalid, "scope_marker_only")[0]
        node["result"] = {"id": 999999, "ty": next(i for i,t in enumerate(invalid["types"]) if t["kind"] == "int" and t["bits"] == 64)}
        case("marker_manufactures_ssa_value", invalid, "noalias scope declaration cannot define an SSA value")
        invalid = clone(); invalid["provenance"]["noalias_metadata_source"].pop()
        case("missing_one_original_node_evidence", invalid, "source node evidence inventory does not match graph")
        invalid = clone(); invalid["provenance"]["noalias_metadata_source"][0]["metadata_kind"] = 5
        case("specialized_node_erased_to_tuple", invalid, "source metadata node is not an MDTuple")
        invalid = clone(); proof = invalid["provenance"]["noalias_metadata_source"][0]
        proof["printer_bytes"][-1] ^= 1
        case("original_printer_bytes_changed_without_digest", invalid, "source metadata printer digest does not match bytes")
        invalid = clone(); node = invalid["noalias_metadata"]["domains"][0]
        node["storage"] = "uniqued" if node["storage"] == "distinct" else "distinct"
        case("original_storage_class_erased", invalid, "source metadata printer storage prefix does not match graph")
        invalid = clone(); proof = invalid["provenance"]["noalias_metadata_source"][0]
        proof["printer_bytes"] = list(b'untrusted\0\xff = distinct !{}')
        proof["printer_sha256"] = hashlib.sha256(bytes(proof["printer_bytes"])).hexdigest()
        case("invalid_binary_printer_label_even_with_matching_hash", invalid, "source metadata printer storage prefix does not match graph")
        invalid = clone(); invalid["noalias_metadata"]["attachments"][0]["site"]["function"] = MARKER
        case("attachment_on_compiler_declaration", invalid, "attachment references an unknown function definition")
        invalid = clone(); invalid["noalias_metadata"]["attachments"][0]["site"]["instruction"] = MASK
        case("attachment_range_out_of_bounds", invalid, "attachment native instruction range is out of bounds")
        invalid = clone(); node = next(row for row in invalid["noalias_metadata"]["attachments"] if row["site"]["instruction_count"] == 3)
        node["site"]["instruction_count"] = 4
        case("one_to_many_attachment_overlaps_next_source_instruction", invalid, "source instruction ranges overlap or are out of order")
        invalid = clone(); attachments = invalid["noalias_metadata"]["attachments"]
        attachments.append(json.loads(json.dumps(attachments[0])))
        case("duplicate_original_attachment_site", invalid, "duplicate source instruction attachment")
        invalid = clone(); node = next(row for row in invalid["noalias_metadata"]["attachments"] if row["site"]["function"] == "scope_cold_unused")
        node["site"]["source_instruction"] = 0
        case("cold_attachment_reassigned_to_marker_source", invalid, "marker and attachment source ranges differ")
        invalid = clone(); function(invalid, MARKER)["intrinsic"] = MARKER + ".fake"
        case("intrinsic_prefix_is_not_ownership", invalid, "invalid or unsupported intrinsic declaration")
        invalid = clone(); function(invalid, MARKER)["entry"] = 0
        function(invalid, MARKER)["blocks"] = [{"id": 0, "instructions": [], "terminator": {"op": "return", "value": None}}]
        case("compiler_declaration_manufactures_body", invalid, "invalid or unsupported intrinsic declaration")
        invalid = clone(); metadata = next(i for i,t in enumerate(invalid["types"]) if t["kind"] == "metadata")
        next(g for g in invalid["globals"] if g["name"] == "effect_log")["ty"] = metadata
        case("metadata_as_global_storage", invalid, "unsized")
        invalid = clone(); metadata = next(i for i,t in enumerate(invalid["types"]) if t["kind"] == "metadata")
        ordinary = function(invalid, "scope_empty")
        ordinary["signature"]["params"] = [metadata]; ordinary["signature"]["param_attributes"] = [[]]
        ordinary["params"] = [{"id": 999999, "ty": metadata}]
        case("metadata_as_ordinary_argument", invalid, "unsized")
        invalid = clone(); pointer = next(i for i,t in enumerate(invalid["types"]) if t["kind"] == "pointer" and t["address_space"] == 0)
        function(invalid, "scope_empty")["blocks"][0]["instructions"].append({"result": {"id": 999999, "ty": pointer},
            "operation": {"op": "freeze", "value": {"kind": "symbol", "ty": pointer, "name": MARKER}}})
        case("compiler_marker_address_is_not_runtime_provider", invalid, "intrinsic address")
        controls = []
        for name, invalid, expected in cases:
            path = original.with_name(original.name+".negative-"+name+".json")
            path.write_text(json.dumps(invalid, indent=2)+"\n")
            result = self.command([self.compiler, path, "--input-kind", "native-ir", "--verify-native"], success=False)
            self.assertNotEqual(result.returncode, 0, "invalid scoped alias contract must be rejected: " + name)
            diagnostic = result.stderr.decode()
            self.assertIn(expected, diagnostic, "the specific semantic guard must reject: " + name)
            self.assertNotIn("invalid native module:", diagnostic, "schema-valid negative must reach native verification")
            controls.append({"case": name, "input": self.bind(path), "schema_valid": True,
                             "expected_diagnostic": expected, "diagnostic": diagnostic, "exit_code": result.returncode})
        return controls

    def whole_module(self, source, target, inventory, source_sites):
        output, verification = source.with_name(source.name+".native.json"), source.with_name(source.name+".verified.json")
        self.command([self.compiler, source, "--input-kind", "llvm-ir", "--target", target, "--emit", "mir", "-o", output])
        self.command([self.compiler, output, "--input-kind", "native-ir", "--verify-native", "--receipt", verification])
        module = json.loads(output.read_text())
        self.assertEqual({f["name"] for f in module["functions"]}, set(inventory["functions"]))
        self.assertEqual({f["name"] for f in module["functions"] if f["entry"] is not None}, DEFINITIONS)
        self.assertEqual({g["name"] for g in module["globals"]}, set(inventory["globals"]))
        self.assertEqual(module["aliases"], [])
        self.assertEqual(module["provenance"]["source_function_count"], 9)
        self.assertEqual(module["provenance"]["source_global_count"], 4)
        self.assertEqual(module["provenance"]["input_sha256"], self.bind(source)["sha256"])
        self.assertEqual(json.loads(verification.read_text())["module_sha256"], self.bind(output)["sha256"])
        graph = self.check_graph(module, source_sites, inventory)
        return module, {"module": self.bind(output), "verification": self.bind(verification), "graph": graph}

    def object_contract(self, obj, isa, machine):
        elf(obj, machine, 1)
        decoded = frames.Elf(obj.read_bytes())
        self.assertFalse(any(MARKER in symbol["name"] for symbol in decoded.symbols),
                         "compiler declaration may not manufacture even a local NOTYPE label")
        self.assertFalse(any(symbol["name"] and symbol["section"] == 0 for symbol in decoded.symbols),
                         "whole fixture needs no undefined intrinsic or external runtime provider")
        defined_symbols = [value for value in decoded.symbols if value["info"] & 15 == 2 and value["section"]]
        self.assertEqual(len(defined_symbols), len(DEFINITIONS), "one actual symbol record must own each original definition")
        definitions = {value["name"]: value for value in defined_symbols}
        self.assertEqual(set(definitions), DEFINITIONS)
        extents = []
        for value in defined_symbols:
            self.assertGreater(value["size"], 0)
            self.assertTrue(decoded.sections[value["section"]]["flags"] & 4, "function must own executable section bytes")
            self.assertLessEqual(value["value"] + value["size"], len(decoded.section_data(value["section"])))
            extent = (value["section"], value["value"], value["size"])
            self.assertNotIn(extent, extents, "separate original function definitions must retain distinct ranges")
            for section, start, size in extents:
                if section == value["section"]:
                    self.assertTrue(value["value"] + value["size"] <= start or start + size <= value["value"],
                                    "separate original function ranges may not overlap")
            extents.append(extent)
        bodies = {name: decoded.section_data(value["section"])[value["value"]:value["value"]+value["size"]]
                  for name, value in definitions.items()}
        self.assertTrue(bodies["scope_empty"])
        for name in EMPTY_BODIES:
            self.assertEqual(bodies[name], bodies["scope_empty"], "marker-only functions must add no machine opcode or frame work")
        actual_frames = frames.dwarf_frames(decoded, isa)
        owners = {(value["section"], value["value"], value["size"]): name for name, value in definitions.items()}
        self.assertEqual(len(actual_frames), len(DEFINITIONS))
        actual_extents = [(f["code_section"], f["start"], f["size"]) for f in actual_frames]
        self.assertEqual(len(set(actual_extents)), len(actual_extents), "exactly one FDE must own each original source function")
        self.assertEqual(set(actual_extents), set(owners),
                         "actual FDE ranges must own exactly the original source function bodies")
        self.assertTrue(all(not f["cie"]["personality"] and f["lsda"] is None for f in actual_frames))
        output = obj.with_name(obj.name+".llvm-readobj.txt")
        observed = self.command([self.sdk/"llvm-readobj", "--symbols", "--relocations", "--unwind", obj])
        output.write_bytes(observed.stdout); self.bind(output)
        return {"source_definitions": len(DEFINITIONS), "actual_owned_fdes": len(actual_frames),
                "fde_owners": [owners[(f["code_section"], f["start"], f["size"])] for f in actual_frames],
                "marker_companion_body_bytes": len(bodies["scope_empty"]),
                "byte_identical_empty_and_marker_functions": sorted(EMPTY_BODIES),
                "compiler_intrinsic_symbol_or_provider": False, "llvm_readobj": self.bind(output)}

    def object_controls(self, obj, isa, machine):
        """Corrupt only fresh copies to check the independent ELF/FDE oracle."""
        decoded = frames.Elf(obj.read_bytes())
        section = decoded.sections[decoded.named["scope_empty"]["section"]]["name"]
        fake = obj.with_name(obj.name+".fake-compiler-label.o")
        self.command([self.sdk/"llvm-objcopy", "--add-symbol", MARKER+"="+section+":0,local", obj, fake])
        elf(fake, machine, 1)
        self.assertEqual(frames.Elf(fake.read_bytes()).named[MARKER]["info"] & 15, 0,
                         "the control must inject an actual STT_NOTYPE label")
        with self.assertRaisesRegex(AssertionError, "compiler declaration may not manufacture"):
            self.object_contract(fake, isa, machine)
        original_frame = frames.dwarf_frames(decoded, isa)[0]
        data = bytearray(obj.read_bytes())
        position = decoded.sections[original_frame["section"]]["offset"] + original_frame["range_position"]
        data[position:position+4] = (original_frame["size"] + 1).to_bytes(4, "little")
        wrong = obj.with_name(obj.name+".wrong-fde-owner.o"); wrong.write_bytes(data)
        with self.assertRaisesRegex(AssertionError, "actual FDE ranges must own exactly"):
            self.object_contract(wrong, isa, machine)
        return [{"case": "local_notype_compiler_label", "object": self.bind(fake), "rejected_by_independent_oracle": True},
                {"case": "fde_wrong_source_function_extent", "object": self.bind(wrong), "rejected_by_independent_oracle": True}]

    def test_whole_original_noalias_scopes_reference_and_own_execution_all_three(self):
        # Calling this method before the coherent compiler is available requires
        # the explicit reference-only setting; no live importer is called then.
        from tests.test_ocore_native_allocsize import AllocsizeNativeTests
        emulators = AllocsizeNativeTests.emulators(self)
        reference_only = os.environ.get("OCORE_TEST_NOALIAS_REFERENCE_ONLY") == "1"
        tools = {"clang": self.sdk/"clang", "llvm-as": self.sdk/"llvm-as", "llvm-readobj": self.sdk/"llvm-readobj",
                 "lld": self.linker, "llvm_library": importer.discover_library(), **emulators}
        if not reference_only:
            tools["ocorec"] = self.compiler
            tools["llvm-objcopy"] = self.sdk/"llvm-objcopy"
        for tool in tools.values(): self.bind(tool)
        self.bind(__file__)
        snapshot = self.directory/"test-source-snapshot.py"; snapshot.write_bytes(Path(__file__).read_bytes()); self.bind(snapshot)
        helper_snapshots = []
        for module in (weak, frames, importer, weak.baseline, weak.promises, weak.memory, weak.native, weak.capture_qa):
            source = Path(module.__file__).resolve(); copied = self.directory/(module.__name__.replace(".", "_")+".py")
            copied.write_bytes(source.read_bytes())
            helper_snapshots.append({"module": module.__name__, "original": self.bind(source), "snapshot": self.bind(copied)})
        driver = self.directory/"test-carrier.c"; driver.write_text(carrier()); self.bind(driver)
        report = {"scope": "whole LLVM noalias scope compiler conformance on freestanding Linux carriers",
                  "reference_only": reference_only, "noalias_native_execution_qualified": False,
                  "runtime_complete": False, "full_rust_compiler_complete": False, "dependency_closure_complete": False,
                  "provider_modules_lowered": False, "native_ostadix_qualified": False,
                  "kernel_execution_verified": False, "physical_silicon_qualified": False,
                  "test_source": self.bind(snapshot), "helper_source_snapshots": helper_snapshots,
                  "golden_stdout": golden().decode(), "cases_per_execution": len(vectors()),
                  "source_fixture": "complete synthetic compiler regression module, not an imported runtime substitute",
                  "process_environment": {key: os.environ.get(key) for key in
                      ("PATH", "LD_LIBRARY_PATH", "LD_LLD", "OCOREC", "OCORE_TEST_LLVM22_BIN",
                       "OCORE_TEST_QEMU_AARCH64", "OCORE_TEST_QEMU_RISCV64", "OCORE_TEST_REQUIRE_ALL_ISAS",
                       "OCORE_TEST_NOALIAS_REFERENCE_ONLY")},
                  "targets": {}, "passed": False}
        receipt = self.directory/"report.json"
        try:
            for isa, (target, triple, machine, flags) in TARGETS.items():
                with self.subTest(isa=isa):
                    source = self.directory/(isa+"-whole.ll")
                    source.write_text(weak.promises.module_text(target, llvm_body())); self.bind(source)
                    bitcode = source.with_suffix(".bc"); self.command([self.sdk/"llvm-as", source, "-o", bitcode]); self.bind(bitcode)
                    carriers = {}
                    for corrupt in (False, True):
                        output = self.directory/(isa+"-carrier"+("-corrupt" if corrupt else "")+".o")
                        self.command([self.sdk/"clang", "--target="+triple, *flags, "-O0", "-ffreestanding", "-fno-builtin",
                                      "-fno-stack-protector", "-fno-pic", "-fno-pie", *( ["-DCORRUPT_ORACLE"] if corrupt else []),
                                      "-c", driver, "-o", output]); self.bind(output); carriers[corrupt] = output
                    report["targets"][isa] = []
                    for original in (source, bitcode):
                        inventory, sites = self.original_sites(original)
                        row = {"input": self.bind(original), "whole_original_inventory": inventory,
                               "original_source_sites": sites, "executions": {}}
                        report["targets"][isa].append(row)
                        obj = original.with_name(original.name+".reference.o")
                        self.command([self.sdk/"clang", "--target="+triple, *flags, "-O0", "-fno-pic", "-fno-pie", "-c", original, "-o", obj])
                        elf(obj, machine, 1); self.bind(obj)
                        for own in (False, True):
                            if own:
                                if reference_only: continue
                                module, row["whole_verified_import"] = self.whole_module(original, target, inventory, sites)
                                row["independent_source_preservation_controls"] = self.source_preservation_controls(original, module, sites, inventory)
                                row["admission_controls"] = self.admission_controls(original, module)
                                obj = original.with_name(original.name+".own.o")
                                self.command([self.compiler, original, "--input-kind", "llvm-ir", "--target", target, "-o", obj])
                                self.bind(obj); row["owned_object_contract"] = self.object_contract(obj, isa, machine)
                                row["independent_corrupt_object_controls"] = self.object_controls(obj, isa, machine)
                                assembly = original.with_name(original.name+".own.s")
                                self.command([self.compiler, original, "--input-kind", "llvm-ir", "--target", target, "--emit", "asm", "-o", assembly])
                                assembly_text = assembly.read_text()
                                self.assertEqual(assembly_text.count(".cfi_startproc"), len(DEFINITIONS))
                                self.assertEqual(assembly_text.count(".cfi_endproc"), len(DEFINITIONS))
                                self.assertNotIn(MARKER+":", assembly_text, "compiler declaration must emit no native body label")
                                row["owned_whole_assembly"] = self.bind(assembly)
                            tag = "own" if own else "reference"
                            for corrupt in (False, True):
                                binary = self.directory/(isa+"-"+original.suffix[1:]+"-"+tag+("-corrupt" if corrupt else ""))
                                linked = self.command([self.sdk/"clang", "--target="+triple, *flags, "-nostdlib", "-static", "-fuse-ld=lld",
                                                       "-Wl,-e,_start", "-Wl,--build-id=none", "-Wl,--trace", carriers[corrupt], obj, "-o", binary])
                                ordered = []
                                for line in linked.stdout.decode().splitlines():
                                    path = str(Path(line).resolve())
                                    self.assertIn(path, self.bound, "unknown actual linker provider/test-carrier input: " + line)
                                    ordered.append(self.bound[path])
                                self.assertEqual(len(ordered), 2)
                                executed = self.command(([emulators[isa]] if isa != "x86_64" else [])+[binary], success=not corrupt)
                                self.assertEqual(executed.returncode, 31 if corrupt else 0)
                                if not corrupt: self.assertEqual(executed.stdout, golden()); self.assertEqual(executed.stderr, b"")
                                row["executions"][tag+("_corrupt" if corrupt else "")] = {"executable": self.bind(binary),
                                    "ordered_actual_link_inputs": ordered, "exit_code": executed.returncode,
                                    "stdout": executed.stdout.decode(), "stderr": executed.stderr.decode()}
                    receipt.write_text(json.dumps(report, indent=2)+"\n")
            for item in list(self.bound.values()): self.bind(item["path"])
            self.assertEqual(set(report["targets"]), set(TARGETS))
            expected = {"reference", "reference_corrupt"}
            if not reference_only: expected |= {"own", "own_corrupt"}
            self.assertTrue(all(len(rows) == 2 and all(set(row["executions"]) == expected for row in rows)
                                for rows in report["targets"].values()))
            if not reference_only:
                self.assertTrue(all(len(row["admission_controls"]) == 26 and
                                    len(row["independent_source_preservation_controls"]) == 2 and
                                    len(row["independent_corrupt_object_controls"]) == 2
                                    for rows in report["targets"].values() for row in rows))
            report["noalias_native_execution_qualified"] = not reference_only
            report["passed"] = True
        finally:
            report["bound_inputs_tools_outputs"] = list(self.bound.values())
            report["commands"] = [weak.artifact(path) for path in sorted(self.directory.glob("command-*.json"))]
            receipt.write_text(json.dumps(report, indent=2)+"\n")


if __name__ == "__main__":
    unittest.main()
