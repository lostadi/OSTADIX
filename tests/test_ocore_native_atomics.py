"""Whole original LLVM/C atomic conformance on three Linux coherent-RAM ISAs.

The raw LLVM fixture covers the admitted coherent-RAM i8/i16/i32/i64 profile;
the unchanged C fixture is compiled separately by each genuine target frontend.
Original LL and BC, including cold definitions, are imported and emitted whole.
An independent Clang carrier and original source-built musl create real pthreads
and mix Clang/O-core accesses to the same objects. Those supplied test providers
are reference inputs, not evidence of O-core provider or compiler completeness.
QEMU observations do not prove silicon weak ordering or exclusive-loop progress.
"""
import ctypes as C
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile
import time
import unittest

from scripts import ocore_llvm_import as importer
from scripts.check_ocore_native_equivalence import TARGETS
from tests import test_ocore_native_eh_execution as providers
from tests import test_ocore_native_eh_objects as frames
from tests import test_ocore_native_weak as weak

MASK = (1 << 64) - 1
PROFILE = "coherent-ram-v1"
JSON_PROFILE = "coherent_ram_v1"
STEPS = 2051
KINDS = ("xchg", "add", "sub", "and", "nand", "or", "xor", "max", "min",
         "umax", "umin", "uinc_wrap", "udec_wrap", "usub_cond", "usub_sat")
# LLVM-C ordinals differ from the C++ enumeration for these newer operations.
RMW_NAMES = dict(enumerate(KINDS[:11])) | {15: "uinc_wrap", 16: "udec_wrap",
                                         17: "usub_cond", 18: "usub_sat"}
ORDERS = {1: "unordered", 2: "monotonic", 4: "acquire", 5: "release", 6: "acq_rel", 7: "seq_cst"}
LOAD_ORDERS = ("unordered", "monotonic", "acquire", "seq_cst")
STORE_ORDERS = ("unordered", "monotonic", "release", "seq_cst")
CAS_ORDERS = tuple((success, failure) for success in
                   ("monotonic", "acquire", "release", "acq_rel", "seq_cst")
                   for failure in ("monotonic", "acquire", "seq_cst"))


def vectors(bits):
    mask, high = (1 << bits) - 1, 1 << (bits - 1)
    corners = (0, 1, mask, mask >> 1, high, mask - 1, high - 1, (high + 1) & mask)
    result = [(old, val) for old in corners for val in corners]
    state = 0x173face912fea565
    for _ in range(64):
        values = []
        for _ in range(2):
            state ^= state << 13 & MASK; state ^= state >> 7; state ^= state << 17 & MASK
            state &= MASK; values.append(state & mask)
        result.append(tuple(values))
    return result


def updated(kind, old, val, bits):
    mask, high = (1 << bits) - 1, 1 << (bits - 1)
    signed = lambda value: value - (1 << bits) if value & high else value
    values = {"xchg": val, "add": old + val, "sub": old - val,
              "and": old & val, "nand": ~(old & val), "or": old | val, "xor": old ^ val,
              "max": old if signed(old) > signed(val) else val,
              "min": old if signed(old) < signed(val) else val,
              "umax": max(old, val), "umin": min(old, val),
              "uinc_wrap": 0 if old >= val else old + 1,
              "udec_wrap": val if old == 0 or old > val else old - 1,
              "usub_cond": old - val if old >= val else old,
              "usub_sat": old - val if old >= val else 0}
    return values[kind] & mask


def scoped(scope):
    return 'syncscope("singlethread") ' if scope == 0 else ""


def llvm_body():
    text = "@atomic_cold = global i64 707, align 8\n@atomic_cold_pointer = global ptr @atomic_cold, align 8\n"
    definitions = set()
    for bits in (8, 16, 32, 64):
        for scope in (0, 1):
            for index, kind in enumerate(KINDS):
                name = f"a_{bits}_{kind}" + ("_single" if scope == 0 else "")
                definitions.add(name)
                text += f"define i64 @{name}(ptr %p, i64 %value) {{\n"
                value = "%value"
                if bits != 64: text += f"  %v = trunc i64 %value to i{bits}\n"; value = "%v"
                order = ("monotonic", "acquire", "release", "acq_rel", "seq_cst")[index % 5]
                text += f"  %old = atomicrmw volatile {kind} ptr %p, i{bits} {value} {scoped(scope)}{order}, align {bits // 8}\n"
                if bits != 64: text += f"  %ret = zext i{bits} %old to i64\n"; ret = "%ret"
                else: ret = "%old"
                text += f"  ret i64 {ret}\n}}\n"
        for pair, (success, failure) in enumerate(CAS_ORDERS):
            for is_weak in (0, 1):
                name = f"cas_{bits}_{pair}_{is_weak}"; definitions.add(name)
                text += f"define void @{name}(ptr %p, i64 %expected, i64 %replacement, ptr %out) {{\n"
                expected, replacement = "%expected", "%replacement"
                if bits != 64:
                    text += f"  %e = trunc i64 %expected to i{bits}\n  %v = trunc i64 %replacement to i{bits}\n"
                    expected, replacement = "%e", "%v"
                scope = scoped(pair & 1)
                text += f"  %pair = cmpxchg {'weak ' if is_weak else ''}volatile ptr %p, i{bits} {expected}, i{bits} {replacement} {scope}{success} {failure}, align {bits // 8}\n"
                text += f"  %old = extractvalue {{i{bits}, i1}} %pair, 0\n  %flag = extractvalue {{i{bits}, i1}} %pair, 1\n"
                if bits != 64: text += f"  %wide = zext i{bits} %old to i64\n"; old = "%wide"
                else: old = "%old"
                text += f"  %flag64 = zext i1 %flag to i64\n  %second = getelementptr i64, ptr %out, i64 1\n  store i64 {old}, ptr %out, align 8\n  store i64 %flag64, ptr %second, align 8\n  ret void\n}}\n"
        for scope in (0, 1):
            for index, order in enumerate(LOAD_ORDERS):
                name = f"load_{bits}_{scope}_{index}"; definitions.add(name)
                text += f"define i64 @{name}(ptr %p) {{\n  %old = load atomic volatile i{bits}, ptr %p {scoped(scope)}{order}, align {bits // 8}\n"
                if bits != 64: text += f"  %ret = zext i{bits} %old to i64\n"; old = "%ret"
                else: old = "%old"
                text += f"  ret i64 {old}\n}}\n"
            for index, order in enumerate(STORE_ORDERS):
                name = f"store_{bits}_{scope}_{index}"; definitions.add(name)
                text += f"define void @{name}(ptr %p, i64 %value) {{\n"
                value = "%value"
                if bits != 64: text += f"  %v = trunc i64 %value to i{bits}\n"; value = "%v"
                text += f"  store atomic volatile i{bits} {value}, ptr %p {scoped(scope)}{order}, align {bits // 8}\n  ret void\n}}\n"
    for scope in (0, 1):
        for index, order in enumerate(("acquire", "release", "acq_rel", "seq_cst")):
            name = f"fence_{scope}_{index}"; definitions.add(name)
            text += f"define void @{name}() {{\n  fence {scoped(scope)}{order}\n  ret void\n}}\n"
    for pair, (success, failure) in enumerate(CAS_ORDERS):
        for is_weak in (0, 1):
            name = f"ptr_cas_{pair}_{is_weak}"; definitions.add(name)
            text += f"define void @{name}(ptr %p, ptr %expected, ptr %replacement, ptr %out) {{\n"
            text += f"  %pair = cmpxchg {'weak ' if is_weak else ''}volatile ptr %p, ptr %expected, ptr %replacement {scoped(pair & 1)}{success} {failure}, align 8\n"
            text += "  %old = extractvalue {ptr, i1} %pair, 0\n  %flag = extractvalue {ptr, i1} %pair, 1\n  %wide = zext i1 %flag to i64\n  %second = getelementptr i64, ptr %out, i64 1\n  store ptr %old, ptr %out, align 8\n  store i64 %wide, ptr %second, align 8\n  ret void\n}\n"
    text += r'''
define ptr @ptr_xchg(ptr %p, ptr %value) {
  %old = atomicrmw volatile xchg ptr %p, ptr %value seq_cst, align 8
  ret ptr %old
}
define ptr @ptr_load(ptr %p) {
  %old = load atomic volatile ptr, ptr %p acquire, align 8
  ret ptr %old
}
define void @ptr_store(ptr %p, ptr %value) {
  store atomic volatile ptr %value, ptr %p release, align 8
  ret void
}
define ptr @atomic_cold_unused() {
  %value = load ptr, ptr @atomic_cold_pointer, align 8
  %old = atomicrmw volatile xchg ptr @atomic_cold_pointer, ptr %value syncscope("singlethread") monotonic, align 8
  ret ptr %old
}
@atomic_cold_alias = alias ptr (), ptr @atomic_cold_unused
'''
    definitions.update(("ptr_xchg", "ptr_load", "ptr_store", "atomic_cold_unused"))
    return text, definitions


C_SOURCE = r'''
#include <stdint.h>
extern unsigned long a_8_add(void *,unsigned long);
extern unsigned long a_16_add(void *,unsigned long);
extern unsigned long a_32_add(void *,unsigned long);
extern unsigned long a_64_add(void *,unsigned long);
static unsigned long c_cold = 911;
__attribute__((noinline)) unsigned long atomic_thread_step(unsigned long id,
  void *bytes,void *halves,void *count32,void *count64,
  unsigned long a0,unsigned long a1,unsigned long a2,unsigned long a3,
  unsigned long a4,unsigned long a5,unsigned long a6,unsigned long a7,
  unsigned long a8,unsigned long a9,unsigned long a10) {
  volatile unsigned char frame[8193];frame[0]=(unsigned char)id;frame[8192]=7;
  a_8_add((unsigned char*)bytes+id,1);
  a_16_add((unsigned short*)halves+(id&1),1);
  a_32_add(count32,1);a_64_add(count64,1);
  return a0+2*a1+3*a2+4*a3+5*a4+6*a5+7*a6+8*a7+9*a8+10*a9+11*a10+
    frame[0]+frame[8192];
}
unsigned long c_original_atomic_contract(void *address,unsigned long value) {
  volatile unsigned long *p=address;
  __atomic_store_n(p,value,__ATOMIC_RELEASE);
  unsigned long loaded=__atomic_load_n(p,__ATOMIC_ACQUIRE);
  unsigned long old=__atomic_fetch_xor(p,0x55,__ATOMIC_ACQ_REL);
  unsigned long expected=loaded^0x55;
  int success=__atomic_compare_exchange_n(p,&expected,value,0,__ATOMIC_SEQ_CST,__ATOMIC_ACQUIRE);
  __atomic_thread_fence(__ATOMIC_SEQ_CST);
  __atomic_signal_fence(__ATOMIC_SEQ_CST);
  return loaded+old+expected+(unsigned long)success;
}
unsigned long c_atomic_cold_unused(void) {
  return __atomic_fetch_add(&c_cold,0,__ATOMIC_RELAXED);
}
'''


def golden_values():
    for bits in (8, 16, 32, 64):
        for old, val in vectors(bits):
            for _ in (0, 1):
                for kind in KINDS: yield from (old, updated(kind, old, val, bits), 1)
            for _ in CAS_ORDERS:
                for _ in (0, 1):
                    for success in (0, 1): yield from (old, success, val if success else old, 1)
            for _ in range(8): yield from (old, 1)
            for _ in range(8): yield from (val, 1)
    yield from [1] * 8  # each fence function is called
    yield from [1] * 4  # pointer xchg/load/store effects
    yield from [1] * (len(CAS_ORDERS) * 2 * 2 * 4)
    yield 13 + 13 + (13 ^ 0x55) + 1  # genuine C builtins
    yield 13  # final genuine C atomic storage
    yield from ((11 + 2*STEPS) & 255, (19 + 2*STEPS) & 255,
                (23 + 2*STEPS) & 255, (31 + 2*STEPS) & 255, 167, 167, 167, 167)
    yield from (103 + 4*STEPS, 211 + 4*STEPS, 317, 419, 8*STEPS, 8*STEPS)
    yield from [1] * 8  # sixteen-argument participant results remain exact
    yield from (1, STEPS*17+31, 1, STEPS*17+31)  # both mixed-direction handshakes


def golden():
    digest, checks = 0xcbf29ce484222325, 0
    for value in golden_values(): digest = (digest ^ value) * 0x100000001b3 & MASK; checks += 1
    return f"OCORE-ATOMIC digest={digest:016x} checks={checks} threads=8 steps={STEPS}\n".encode()


def carrier():
    text = r'''
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sched.h>
typedef unsigned long U;
typedef U (*Rmw)(void*,U);
typedef void (*Cas)(void*,U,U,U*);
typedef U (*Load)(void*);
typedef void (*Store)(void*,U);
typedef void (*PtrCas)(void*,void*,void*,void*);
extern void *ptr_xchg(void*,void*),*ptr_load(void*);
extern void ptr_store(void*,void*);
extern U c_original_atomic_contract(void*,U);
extern U atomic_thread_step(U,void*,void*,void*,void*,U,U,U,U,U,U,U,U,U,U,U);
'''
    for bits in (8, 16, 32, 64):
        for kind in KINDS:
            text += f"extern U a_{bits}_{kind}(void*,U),a_{bits}_{kind}_single(void*,U);\n"
        for pair in range(15):
            for is_weak in (0, 1): text += f"extern void cas_{bits}_{pair}_{is_weak}(void*,U,U,U*);\n"
        for scope in (0, 1):
            for order in range(4):
                text += f"extern U load_{bits}_{scope}_{order}(void*);\nextern void store_{bits}_{scope}_{order}(void*,U);\n"
    for scope in (0, 1):
        for order in range(4): text += f"extern void fence_{scope}_{order}(void);\n"
    for pair in range(15):
        for is_weak in (0, 1): text += f"extern void ptr_cas_{pair}_{is_weak}(void*,void*,void*,void*);\n"
    text += "static Rmw rmws[4][2][15]={\n" + ",\n".join("{" + ",".join("{" + ",".join(f"a_{bits}_{kind}" + ("_single" if scope == 0 else "") for kind in KINDS) + "}" for scope in (0, 1)) + "}" for bits in (8, 16, 32, 64)) + "};\n"
    text += "static Cas cases[4][15][2]={\n" + ",\n".join("{" + ",".join("{" + f"cas_{bits}_{pair}_0,cas_{bits}_{pair}_1" + "}" for pair in range(15)) + "}" for bits in (8, 16, 32, 64)) + "};\n"
    for type_, name, prefix in (("Load", "loads", "load"), ("Store", "stores", "store")):
        text += f"static {type_} {name}[4][8]={{\n" + ",\n".join("{" + ",".join(f"{prefix}_{bits}_{scope}_{order}" for scope in (0, 1) for order in range(4)) + "}" for bits in (8, 16, 32, 64)) + "};\n"
    text += "static PtrCas pointers[15][2]={\n" + ",\n".join("{" + f"ptr_cas_{pair}_0,ptr_cas_{pair}_1" + "}" for pair in range(15)) + "};\n"
    text += "static void(*fences[8])(void)={" + ",".join(f"fence_{scope}_{order}" for scope in (0, 1) for order in range(4)) + "};\n"
    text += "struct Vector{U old,val,next[15];};\nstatic const struct Vector vectors[4][128]={\n"
    text += ",\n".join("{" + ",\n".join("{%dULL,%dULL,{%s}}" %
                   (old, val, ",".join(str(updated(kind, old, val, bits))+"ULL" for kind in KINDS))
                   for old, val in vectors(bits)) + "}" for bits in (8, 16, 32, 64)) + "};\n"
    text += f"#define STEPS {STEPS}\n"
    text += r'''
static U digest=0xcbf29ce484222325UL,checks;
static int add(U got,U expected) {
#ifdef CORRUPT_ORACLE
  if(!checks) expected^=1;
#endif
  if(got!=expected) { fprintf(stderr,"atomic mismatch check=%lu got=%lu expected=%lu\n",checks,got,expected);return 31; }
  digest=(digest^got)*0x100000001b3UL;++checks;return 0;
}
static int neighbors(const unsigned char*before,const unsigned char*after,U offset,U bytes) {
  for(U i=0;i<32;i++)if((i<offset||i>=offset+bytes)&&before[i]!=after[i])return 0;return 1;
}
static _Alignas(8) unsigned char byte_lanes[8]={11,19,23,31,167,167,167,167};
static _Alignas(8) unsigned short half_lanes[4]={103,211,317,419};
static _Alignas(8) uint32_t count32;
static _Alignas(8) U count64;
static pthread_barrier_t ready;
struct Worker{U id;int failure;};
static void *worker(void*argument){
  struct Worker*w=argument;U lane=w->id&3;
  int status=pthread_barrier_wait(&ready);
  if(status&&status!=PTHREAD_BARRIER_SERIAL_THREAD){w->failure=1;return 0;}
  for(U k=0;k<STEPS;k++) {
    if(w->id<4) {
      U wanted=lane+7;for(U j=0;j<11;j++)wanted+=(j+1)*(lane+j+1);
      U got=atomic_thread_step(lane,byte_lanes,half_lanes,&count32,&count64,
        lane+1,lane+2,lane+3,lane+4,lane+5,lane+6,lane+7,lane+8,lane+9,lane+10,lane+11);
      if(got!=wanted){w->failure=2;return 0;}
    } else {
      // These participants remain genuine Clang machine code, including their
      // own target-native atomic instructions. They share the exact objects.
      __atomic_fetch_add(byte_lanes+lane,1,__ATOMIC_SEQ_CST);
      __atomic_fetch_add(half_lanes+(lane&1),1,__ATOMIC_SEQ_CST);
#ifdef CORRUPT_CONCURRENCY
      if(!(w->id==4 && k==0))
#endif
      __atomic_fetch_add(&count32,1,__ATOMIC_SEQ_CST);
      __atomic_fetch_add(&count64,1,__ATOMIC_SEQ_CST);
    }
  }
  return 0;
}
static U flag,payload;
struct Handshake{int own_writer,failure;};
static U read_flag(int own){return own?load_64_1_2(&flag):__atomic_load_n(&flag,__ATOMIC_ACQUIRE);}
static void write_flag(int own,U value){if(own)store_64_1_2(&flag,value);else __atomic_store_n(&flag,value,__ATOMIC_RELEASE);}
static void *writer(void*argument){
  struct Handshake*h=argument;
  for(U k=1;k<=STEPS;k++) {while(read_flag(h->own_writer)!=0)sched_yield();payload=k*17+31;write_flag(h->own_writer,k);}
  return 0;
}
static void *reader(void*argument){
  struct Handshake*h=argument;
  for(U k=1;k<=STEPS;k++) {
    while(read_flag(!h->own_writer)!=k)sched_yield();
    if(payload!=k*17+31)h->failure=1;write_flag(!h->own_writer,0);
  }return 0;
}
int main(void){
  for(U w=0;w<4;w++){
    U bytes=1UL<<w;
    for(U sample=0;sample<128;sample++){
      const struct Vector*v=&vectors[w][sample];U offset=bytes*(1+sample%(16/bytes));
      for(U scope=0;scope<2;scope++)for(U op=0;op<15;op++){
        _Alignas(16) unsigned char cell[32],before[32];memset(cell,0xa5,32);memcpy(cell+offset,&v->old,bytes);memcpy(before,cell,32);
        U old=rmws[w][scope][op](cell+offset,v->val),stored=0;memcpy(&stored,cell+offset,bytes);
        if(add(old,v->old)||add(stored,v->next[op])||add(neighbors(before,cell,offset,bytes),1))return 31;
      }
      for(U pair=0;pair<15;pair++)for(U weak=0;weak<2;weak++)for(U success=0;success<2;success++){
        _Alignas(16) unsigned char cell[32],before[32];memset(cell,0x5a,32);memcpy(cell+offset,&v->old,bytes);memcpy(before,cell,32);
        U actual[2]={MASK_SENTINEL,MASK_SENTINEL},stored=0,expected=success?v->old:(v->old^1),attempts=0;
        do {
          actual[0]=actual[1]=~0UL;
          cases[w][pair][weak](cell+offset,expected,v->val,actual);memcpy(&stored,cell+offset,bytes);
          // Weak source permits spurious failure. Every attempt must return
          // the observed old value and leave old storage on such a failure.
          if(actual[0]!=v->old||actual[1]>1||(!actual[1]&&stored!=v->old))return 32;
          if(!success&&actual[1])return 32;
          if(++attempts>STEPS)return 33;
        }while(weak&&success&&!actual[1]);
        if(add(actual[0],v->old)||add(actual[1],success)||add(stored,success?v->val:v->old)||add(neighbors(before,cell,offset,bytes),1))return 31;
      }
      for(U op=0;op<8;op++){
        _Alignas(16) unsigned char cell[32],before[32];memset(cell,0x35,32);memcpy(cell+offset,&v->old,bytes);memcpy(before,cell,32);
        if(add(loads[w][op](cell+offset),v->old)||add(!memcmp(before,cell,32),1))return 31;
      }
      for(U op=0;op<8;op++){
        _Alignas(16) unsigned char cell[32],before[32];memset(cell,0x73,32);memcpy(before,cell,32);
        stores[w][op](cell+offset,v->val);U stored=0;memcpy(&stored,cell+offset,bytes);
        if(add(stored,v->val)||add(neighbors(before,cell,offset,bytes),1))return 31;
      }
    }
  }
  for(U op=0;op<8;op++){fences[op]();if(add(1,1))return 31;}
  U anchors[3]={11,23,47};void*cell=&anchors[0];
  if(add(ptr_xchg(&cell,&anchors[1])==&anchors[0],1)||add(cell==&anchors[1],1))return 31;
  ptr_store(&cell,&anchors[2]);if(add(cell==&anchors[2],1)||add(ptr_load(&cell)==&anchors[2],1))return 31;
  for(U pair=0;pair<15;pair++)for(U weak=0;weak<2;weak++)for(U success=0;success<2;success++){
    cell=&anchors[0];struct{void*old;U flag;}actual;U attempts=0;
    do {
      actual.old=&anchors[2];actual.flag=~0UL;
      pointers[pair][weak](&cell,success?&anchors[0]:&anchors[2],&anchors[1],&actual);
      if(actual.old!=&anchors[0]||actual.flag>1||(!actual.flag&&cell!=&anchors[0])||(!success&&actual.flag))return 32;
      if(++attempts>STEPS)return 33;
    }while(weak&&success&&!actual.flag);
    if(add(actual.old==&anchors[0],1)||add(actual.flag==success,1)||add(cell==(success?&anchors[1]:&anchors[0]),1)||add(1,1))return 31;
  }
  U ordinary=0;if(add(c_original_atomic_contract(&ordinary,13),13+13+(13^0x55)+1)||add(ordinary,13))return 31;
  struct Worker workers[8];pthread_t threads[8];
  if(pthread_barrier_init(&ready,0,9))return 41;
  for(U k=0;k<8;k++){workers[k]=(struct Worker){.id=k};if(pthread_create(&threads[k],0,worker,&workers[k]))return 42;}
  int status=pthread_barrier_wait(&ready);if(status&&status!=PTHREAD_BARRIER_SERIAL_THREAD)return 43;
  for(U k=0;k<8;k++)if(pthread_join(threads[k],0))return 44;
  if(pthread_barrier_destroy(&ready))return 45;
  U initial[]={11,19,23,31};for(U k=0;k<8;k++)if(add(byte_lanes[k],k<4?(initial[k]+2*STEPS)&255:167))return 31;
  U halves[]={103+4*STEPS,211+4*STEPS,317,419};for(U k=0;k<4;k++)if(add(half_lanes[k],halves[k]))return 31;
  if(add(count32,8*STEPS)||add(count64,8*STEPS))return 31;
  for(U k=0;k<8;k++)if(add(!workers[k].failure,1))return 31;
  for(int own=0;own<2;own++){
    flag=payload=0;struct Handshake h={.own_writer=own};pthread_t producer,consumer;
    if(pthread_create(&producer,0,writer,&h)||pthread_create(&consumer,0,reader,&h))return 46;
    if(pthread_join(producer,0)||pthread_join(consumer,0))return 47;
    if(add(!h.failure&&flag==0,1)||add(payload,STEPS*17+31))return 31;
  }
  printf("OCORE-ATOMIC digest=%016lx checks=%lu threads=8 steps=%u\n",digest,checks,STEPS);
  return 0;
}
'''
    return text.replace("MASK_SENTINEL", "~0UL")


class NativeAtomicsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.compiler = Path(os.environ.get("OCOREC", str(weak.ROOT/"target/debug/ocorec"))).resolve()
        cls.sdk = Path(os.environ.get("OCORE_TEST_LLVM22_BIN", str(weak.SDK))).resolve()
        cls.linker = shutil.which(os.environ.get("LD_LLD", "ld.lld"))
        required = [cls.sdk/name for name in ("clang", "llvm-as", "llvm-nm", "llvm-readobj", "llvm-objcopy")]
        if os.environ.get("OCORE_TEST_ATOMICS_REFERENCE_ONLY") != "1": required.append(cls.compiler)
        missing = [str(path) for path in required if not path.is_file()]
        if cls.linker is None: missing.append("LD_LLD/ld.lld")
        if missing:
            reason = "exact LLVM22 SDK/reference tools required: "+", ".join(missing)
            if os.environ.get("OCORE_TEST_REQUIRE_ALL_ISAS") == "1": raise RuntimeError(reason)
            raise unittest.SkipTest(reason)
        for path in required:
            if path == cls.compiler: continue
            result = subprocess.run([str(path), "--version"], capture_output=True, text=True, timeout=15)
            if result.returncode or not re.search(r"\b(?:clang version|LLVM version) 22\.1\.6\b", result.stdout):
                raise RuntimeError("exact LLVM22.1.6 required: "+str(path))
    bind = providers.NativeEhExecutionTests.bind
    original_record = providers.NativeEhExecutionTests.original_record
    profile = providers.NativeEhExecutionTests.profile
    emulators = providers.NativeEhExecutionTests.emulators
    object_identity = providers.NativeEhExecutionTests.object_identity
    original_inventory = providers.NativeEhExecutionTests.original_inventory

    def setUp(self):
        providers.NativeEhExecutionTests.setUp(self)
        retained = os.environ.get("OCORE_TEST_NATIVE_ATOMICS_OUTPUT_DIR")
        if retained:
            root = Path(retained).expanduser().resolve(); root.mkdir(parents=True, exist_ok=True)
            self.directory = Path(tempfile.mkdtemp(prefix="run-", dir=root))
        else:
            temporary = tempfile.TemporaryDirectory(prefix="ocore-native-atomics-")
            self.addCleanup(temporary.cleanup); self.directory = Path(temporary.name)

    def command(self, argv, success=True, cwd=weak.ROOT):
        argv = [str(item) for item in argv]
        started = time.monotonic()
        record = {"argv": argv, "cwd": str(cwd), "execution_timeout_seconds": 120}
        try:
            result = subprocess.run(argv, cwd=cwd, capture_output=True, timeout=120)
            record.update(exit_code=result.returncode, stdout=result.stdout.decode(errors="replace"),
                          stderr=result.stderr.decode(errors="replace"), timeout=False)
        except subprocess.TimeoutExpired as error:
            record.update(exit_code=None, timeout=True, stdout=(error.stdout or b"").decode(errors="replace"),
                          stderr=(error.stderr or b"").decode(errors="replace"))
            raise
        finally:
            record["elapsed_seconds"] = time.monotonic()-started
            (self.directory/f"command-{self.sequence:03}.json").write_text(json.dumps(record, indent=2)+"\n")
            self.sequence += 1
        if success: self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        return result

    def source_atomics(self, source):
        """Independent typed CAPI census; never call the import decoder.

        LLVMGetOrdering is deliberately never applied to compare-exchange.
        Addresses, values, result identities, both CAS orders, volatility and
        scope IDs are read from genuine verified original instruction handles.
        Our fixtures use precisely the two pinned LLVM built-in scope names;
        custom-name preservation is the separate source-worker gate's scope.
        """
        a = self.library
        context, module, error, message = a.ContextCreate(), importer.P(), importer.P(), importer.P()
        buffer, layout = None, None
        try:
            data = source.read_bytes()
            buffer = a.CreateMemoryBufferWithMemoryRangeCopy(data, len(data), b"independent-atomic-oracle")
            parsed = a.ParseIRInContext2(context, buffer, C.byref(module), C.byref(error))
            self.assertEqual(parsed, 0, C.string_at(error).decode() if error else "LLVM parse failed")
            verified = a.VerifyModule(module, 2, C.byref(message))
            self.assertEqual(verified, 0, C.string_at(message).decode() if message else "LLVM verification failed")
            layout = a.CreateTargetData(a.GetDataLayoutStr(module))

            def ty(value):
                kind = a.GetTypeKind(value)
                if kind == 0: return {"kind": "void"}
                if kind == 8: return {"kind": "int", "bits": a.GetIntTypeWidth(value)}
                if kind == 12: return {"kind": "pointer", "address_space": a.GetPointerAddressSpace(value)}
                self.assertEqual(kind, 10, "atomic oracle only uses exact scalar or CAS pair types")
                fields = (importer.P * a.CountStructElementTypes(value))()
                a.GetStructElementTypes(value, fields)
                return {"kind": "struct", "packed": bool(a.IsPackedStruct(value)),
                        "fields": [ty(field) for field in fields]}

            rows, functions, parameter_counts, blocks_contract = [], {}, {}, {}
            opnames = {27: "atomic_load", 28: "atomic_store", 55: "atomic_fence",
                       56: "atomic_compare_exchange", 57: "atomic_rmw"}
            for function in a.sequence(a.GetFirstFunction, a.GetNextFunction, module):
                name = a.name(function)
                parameter_counts[name] = a.CountParams(function)
                parameters = (importer.P * a.CountParams(function))()
                a.GetParams(function, parameters)
                values = {value: index for index, value in enumerate(parameters)}
                blocks = list(a.sequence(a.GetFirstBasicBlock, a.GetNextBasicBlock, function))
                for block in blocks:
                    for instruction in a.sequence(a.GetFirstInstruction, a.GetNextInstruction, block):
                        if a.GetTypeKind(a.TypeOf(instruction)) != 0: values[instruction] = len(values)

                def operand(value):
                    if value in values: return {"kind": "value", "id": values[value]}
                    shape = ty(a.TypeOf(value))
                    if a.IsAConstantInt(value):
                        return {"kind": "int", "type": shape, "bits": str(a.ConstIntGetZExtValue(value))}
                    if a.IsAConstantPointerNull(value): return {"kind": "null", "type": shape}
                    self.assertTrue(a.IsAGlobalVariable(value) or a.IsAGlobalAlias(value) or a.IsAFunction(value),
                                    "fixture oracle must not silently normalize an unsupported constant expression")
                    return {"kind": "symbol", "type": shape, "name": a.name(value)}

                functions[name] = []
                blocks_contract[name] = []
                for block_index, block in enumerate(blocks):
                    spans, cursor = [], 0
                    terminator = a.GetBasicBlockTerminator(block)
                    for ordinal, instruction in enumerate(a.sequence(a.GetFirstInstruction, a.GetNextInstruction, block)):
                        opcode = a.GetInstructionOpcode(instruction)
                        count = 0 if instruction == terminator else 1
                        operation = None
                        if instruction != terminator:
                            if opcode == 29:
                                # Independent source-layout accounting for the
                                # declared NativeIR GEP offset expansion. Each
                                # dynamic index contributes a cast (if narrow),
                                # multiply (if stride !=1), and offset add.
                                current = a.GetGEPSourceElementType(instruction)
                                for index in range(1, a.GetNumOperands(instruction)):
                                    value = a.GetOperand(instruction, index)
                                    if index > 1 and a.GetTypeKind(current) == 10:
                                        self.assertTrue(a.IsAConstantInt(value))
                                        fields = (importer.P*a.CountStructElementTypes(current))()
                                        a.GetStructElementTypes(current, fields)
                                        current = fields[a.ConstIntGetZExtValue(value)]
                                        continue
                                    if index > 1:
                                        self.assertEqual(a.GetTypeKind(current), 11)
                                        current = a.GetElementType(current)
                                    if not a.IsAConstantInt(value):
                                        count += 1 + int(a.GetIntTypeWidth(a.TypeOf(value)) < 64)
                                        count += int(a.ABISizeOfType(layout, current) != 1)
                                operation = "gep"
                            elif opcode in (27, 28):
                                operation = ("atomic_" if a.GetOrdering(instruction) else "")+("load" if opcode == 27 else "store")
                            elif opcode in opnames: operation = opnames[opcode]
                            elif 8 <= opcode <= 25: operation = "binary"
                            elif 30 <= opcode <= 41 or opcode == 60: operation = "cast"
                            elif opcode == 26: operation = "alloca"
                            elif opcode == 42: operation = "i_cmp"
                            elif opcode == 44: operation = "phi"
                            elif opcode == 46: operation = "select"
                            elif opcode == 53: operation = "extract_value"
                            elif opcode == 54: operation = "insert_value"
                            elif opcode == 68: operation = "freeze"
                            elif opcode == 45:
                                callee = a.GetCalledValue(instruction)
                                self.assertFalse(a.IsAFunction(callee) and a.GetIntrinsicID(callee),
                                                 "fixture intrinsic requires an explicit independent span contract")
                                operation = "call"
                            else: self.fail("fixture opcode requires an independent complete span contract: "+str(opcode))
                        spans.append({"source_instruction": ordinal, "source_opcode": opcode,
                                      "native_instruction": cursor, "native_instruction_count": count,
                                      "native_final_operation": operation,
                                      "source_result_id": values.get(instruction)})
                        cursor += count
                        if opcode not in opnames: continue
                        if opcode in (27, 28) and not a.GetOrdering(instruction): continue
                        self.assertTrue(a.IsAtomic(instruction))
                        row = {"function": name, "block": block_index, "source_instruction": ordinal,
                               "native_instruction": spans[-1]["native_instruction"], "native_instruction_count": 1,
                               "op": opnames[opcode], "sync_scope": a.GetAtomicSyncScopeID(instruction),
                               "result": None if a.GetTypeKind(a.TypeOf(instruction)) == 0 else
                               {"id": values[instruction], "type": ty(a.TypeOf(instruction))}}
                        self.assertIn(row["sync_scope"], (0, 1))
                        if opcode == 56:
                            row.update(weak=bool(a.GetWeak(instruction)),
                                       success_ordering=ORDERS[a.GetCmpXchgSuccessOrdering(instruction)],
                                       failure_ordering=ORDERS[a.GetCmpXchgFailureOrdering(instruction)],
                                       expected=operand(a.GetOperand(instruction, 1)),
                                       replacement=operand(a.GetOperand(instruction, 2)))
                        else:
                            row["ordering"] = ORDERS[a.GetOrdering(instruction)]
                        if opcode != 55:
                            row.update(alignment=a.GetAlignment(instruction), volatile=bool(a.GetVolatile(instruction)),
                                       pointer=operand(a.GetOperand(instruction, 1 if opcode == 28 else 0)))
                        if opcode in (28, 57): row["value"] = operand(a.GetOperand(instruction, 0 if opcode == 28 else 1))
                        if opcode == 57: row["kind"] = RMW_NAMES[a.GetAtomicRMWBinOp(instruction)]
                        rows.append(row); functions[name].append(row)
                    blocks_contract[name].append({"id": block_index, "native_instruction_count": cursor,
                                                  "source_instruction_spans": spans})
            return {"input": self.bind(source), "target_triple": a.GetTarget(module).decode(),
                    "data_layout": a.GetDataLayoutStr(module).decode(),
                    "scope_names": [{"id": 0, "name": list(b"singlethread")}, {"id": 1, "name": []}],
                    "sites": rows, "functions": functions, "parameter_counts": parameter_counts,
                    "blocks_contract": blocks_contract, "atomic_event_count": len(rows)}
        finally:
            if error: a.DisposeMessage(error)
            if message: a.DisposeMessage(message)
            if module: a.DisposeModule(module)
            if buffer: a.DisposeMemoryBuffer(buffer)
            if layout: a.DisposeTargetData(layout)
            a.ContextDispose(context)

    def preserve_atomics(self, module, source):
        self.assertEqual(module["target"]["triple"], source["target_triple"])
        self.assertEqual(module["target"]["data_layout"], source["data_layout"])
        self.assertEqual(sorted(module["atomic_sync_scopes"], key=lambda x: x["id"]), source["scope_names"])

        def shape(identifier):
            ty = dict(module["types"][identifier])
            if ty["kind"] == "struct": ty["fields"] = [shape(child) for child in ty["fields"]]
            return ty

        def operand(value):
            value = dict(value)
            if "ty" in value: value["type"] = shape(value.pop("ty"))
            return value

        actual, matched = [], []
        for function in module["functions"]:
            contracts = source["blocks_contract"][function["name"]]
            self.assertEqual(len(function["blocks"]), len(contracts))
            for block in function["blocks"]:
                contract = next(c for c in contracts if c["id"] == block["id"])
                self.assertEqual(len(block["instructions"]), contract["native_instruction_count"],
                                 "complete original block expansion must retain ordinary and atomic instruction positions")
                for span in contract["source_instruction_spans"]:
                    if not span["native_instruction_count"]: continue
                    final = block["instructions"][span["native_instruction"]+span["native_instruction_count"]-1]
                    self.assertEqual(final["operation"]["op"], span["native_final_operation"],
                                     "source ordinal must own its expected complete native span")
                    self.assertEqual(None if final["result"] is None else final["result"]["id"], span["source_result_id"])
                for index, instruction in enumerate(block["instructions"]):
                    op = instruction["operation"]
                    if not op["op"].startswith("atomic_"): continue
                    row = {"function": function["name"], "block": block["id"], **op,
                           "result": None if instruction["result"] is None else
                           {"id": instruction["result"]["id"], "type": shape(instruction["result"]["ty"])}}
                    for key in ("pointer", "value", "expected", "replacement"):
                        if key in row: row[key] = operand(row[key])
                    row.update(native_instruction=index, native_instruction_count=1)
                    actual.append(row)
                    matched.append({"function": function["name"], "block": block["id"],
                                    "native_instruction": index, "native_instruction_count": 1})
        expected = [{key: value for key, value in site.items() if key != "source_instruction"} for site in source["sites"]]
        self.assertEqual(actual, expected, "original atomic events, SSA operands, widths and exact source metadata must survive")
        self.assertEqual(len(matched), source["atomic_event_count"])
        return [{**original, **native} for original, native in zip(source["sites"], matched)]

    def whole_module(self, original, target, inventory, atomics):
        output, receipt = original.with_name(original.name+".native.json"), original.with_name(original.name+".verified.json")
        self.command([self.compiler, original, "--input-kind", "llvm-ir", "--target", target,
                      "--atomic-profile", PROFILE, "--emit", "mir", "-o", output])
        self.command([self.compiler, output, "--input-kind", "native-ir", "--verify-native", "--receipt", receipt])
        module = json.loads(output.read_text())
        self.assertEqual(module["target"]["atomic_profile"], JSON_PROFILE)
        for singular, plural in (("function", "functions"), ("global", "globals"), ("alias", "aliases")):
            self.assertEqual({x["name"] for x in module[plural]}, set(inventory[plural]))
            self.assertEqual(module["provenance"]["source_"+singular+"_count"], len(inventory[plural]))
        self.assertEqual({f["name"] for f in module["functions"] if f["entry"] is not None}, set(inventory["definitions"]))
        self.assertEqual(module["provenance"]["input_sha256"], self.bind(original)["sha256"])
        self.assertEqual(json.loads(receipt.read_text())["module_sha256"], self.bind(output)["sha256"])
        sites = self.preserve_atomics(module, atomics)
        return module, {"module": self.bind(output), "verification": self.bind(receipt),
                        "source_and_native_atomic_sites": sites, "whole_function_definitions": len(inventory["definitions"])}

    def semantic_controls(self, original, target, module, atomics):
        def clone(): return json.loads(json.dumps(module))
        def first(value, operation, name=None):
            return next(i for f in value["functions"] if name is None or f["name"] == name
                        for b in f["blocks"] for i in b["instructions"] if i["operation"]["op"] == operation)
        cases = []
        def change(label, operation, field, value, diagnostic, name=None):
            bad = clone(); first(bad, operation, name)["operation"][field] = value
            cases.append((label, bad, diagnostic, False))
        change("load_release", "atomic_load", "ordering", "release", "atomic load ordering cannot release")
        change("store_acquire", "atomic_store", "ordering", "acquire", "atomic store ordering cannot acquire")
        change("fence_monotonic", "atomic_fence", "ordering", "monotonic", "atomic fence ordering must be acquire, release, acq_rel or seq_cst")
        change("rmw_unordered", "atomic_rmw", "ordering", "unordered", "atomic RMW ordering must be at least monotonic")
        change("cas_failure_release", "atomic_compare_exchange", "failure_ordering", "release", "atomic compare-exchange ordering is invalid")
        change("cas_success_unordered", "atomic_compare_exchange", "success_ordering", "unordered", "atomic compare-exchange ordering is invalid")
        change("missing_scope", "atomic_rmw", "sync_scope", 8, "atomic synchronization scope is missing from the module inventory")
        change("zero_alignment", "atomic_load", "alignment", 0, "alignment must be a power of two")
        change("invalid_pointer_rmw_kind", "atomic_rmw", "kind", "add", "atomic RMW operation/value type mismatch", "ptr_xchg")
        bad = clone(); pair = first(bad, "atomic_compare_exchange")["result"]["ty"]; bad["types"][pair]["packed"] = True
        cases.append(("packed_cas_result", bad, "atomic compare-exchange result requires original unpacked {T,i1}", False))
        bad = clone(); bad["atomic_sync_scopes"].append(dict(bad["atomic_sync_scopes"][0]))
        cases.append(("duplicate_scope", bad, "duplicate synchronization scope ID or name", False))
        bad = clone(); next(s for s in bad["atomic_sync_scopes"] if s["id"] == 1)["name"] = list(b"system")
        cases.append(("rewritten_builtin_scope_name", bad, "synchronization scope built-in identity/name mismatch", False))
        bad = clone(); bad["target"].pop("atomic_profile")
        cases.append(("missing_realization_profile", bad, "atomic lowering requires the explicit coherent_ram_v1 execution profile", True))
        bad = clone(); first(bad, "atomic_rmw", "a_32_add")["operation"]["alignment"] = 1
        cases.append(("legal_underaligned_source", bad, "under-aligned atomic access", True))
        bad = clone(); bad["atomic_sync_scopes"].append({"id": 8, "name": list(b"system")})
        first(bad, "atomic_rmw")["operation"]["sync_scope"] = 8
        cases.append(("legal_custom_scope", bad, "custom atomic synchronization scope needs a target-specific realization", True))
        controls = []
        for label, bad, diagnostic, source_valid in cases:
            path = original.with_name(original.name+".negative-"+label+".json")
            path.write_text(json.dumps(bad, indent=2)+"\n")
            if source_valid:
                self.command([self.compiler, path, "--input-kind", "native-ir", "--verify-native"])
                output = path.with_suffix(".rejected.o")
                argv = [self.compiler, path, "--input-kind", "native-ir", "--target", target, "-o", output]
            else:
                output = None; argv = [self.compiler, path, "--input-kind", "native-ir", "--verify-native"]
            result = self.command(argv, success=False)
            self.assertNotEqual(result.returncode, 0, "control must reject the intended contract: "+label)
            self.assertIn(diagnostic, result.stderr.decode(), label)
            self.assertNotIn("invalid native module:", result.stderr.decode(), "semantic control must be schema-valid: "+label)
            if output: self.assertFalse(output.exists())
            controls.append({"case": label, "input": self.bind(path), "schema_valid": True,
                             "valid_source_contract": source_valid, "exit_code": result.returncode,
                             "expected_diagnostic": diagnostic, "diagnostic": result.stderr.decode()})
        output = original.with_name(original.name+".unknown-profile.json")
        result = self.command([self.compiler, original, "--input-kind", "llvm-ir", "--atomic-profile", "device-v1",
                               "--emit", "mir", "-o", output], success=False)
        self.assertNotEqual(result.returncode, 0); self.assertIn("invalid value 'device-v1'", result.stderr.decode())
        self.assertFalse(output.exists())
        controls.append({"case": "unknown_cli_profile", "exit_code": result.returncode, "diagnostic": result.stderr.decode()})
        # A verifier-valid authored alternative is not cryptographically bound
        # to source semantics. This independent comparison must catch it.
        for label, op, field, value in (("source_order_rewrite", "atomic_load", "ordering", "monotonic"),
                                        ("source_scope_rewrite", "atomic_rmw", "sync_scope", 1),
                                        ("source_weak_rewrite", "atomic_compare_exchange", "weak", True)):
            bad = clone()
            instruction = next(i for f in bad["functions"] for b in f["blocks"] for i in b["instructions"]
                               if i["operation"]["op"] == op and i["operation"].get(field) != value)
            instruction["operation"][field] = value
            with self.assertRaisesRegex(AssertionError, "original atomic events"):
                self.preserve_atomics(bad, atomics)
            path = original.with_name(original.name+".oracle-control-"+label+".json")
            path.write_text(json.dumps(bad, indent=2)+"\n")
            controls.append({"case": label, "input": self.bind(path), "independent_source_oracle_rejected": True})
        return controls

    def owned_object(self, path, isa, machine, module):
        self.object_identity(path, machine)
        elf = frames.Elf(path.read_bytes())
        source_definitions = {f["name"] for f in module["functions"] if f["entry"] is not None}
        aliases = {a["name"]: a["aliasee"] for a in module["aliases"]}
        functions = [s for s in elf.symbols if s["section"] and s["info"] & 15 == 2]
        self.assertEqual(len({s["name"] for s in functions}), len(functions), "duplicate actual function symbol records")
        self.assertEqual({s["name"] for s in functions}, source_definitions | set(aliases))
        function_symbols = {symbol["name"]: symbol for symbol in functions}
        for name in source_definitions | set(aliases):
            self.assertEqual(sum(symbol["name"] == name for symbol in elf.symbols), 1,
                             "source function name requires exactly one actual named symbol record")
        defined = {name: function_symbols[name] for name in source_definitions}
        self.assertEqual(len(functions), len(source_definitions)+len(aliases),
                         "exactly one actual symbol record must own each definition or declared alias")
        extents = {(s["section"], s["value"], s["size"]) for s in defined.values()}
        self.assertTrue(all(s["size"] > 0 for s in defined.values()))
        self.assertEqual(len(extents), len(defined), "each original function owns its complete distinct native body")
        prior = []
        for name, symbol in defined.items():
            section = elf.sections[symbol["section"]]
            self.assertTrue(section["flags"] & 4, "function must own executable section bytes")
            self.assertLessEqual(symbol["value"]+symbol["size"], len(elf.section_data(symbol["section"])),
                                 "complete function extent must fit its original section bytes")
            for other in prior:
                if other["section"] == symbol["section"]:
                    self.assertTrue(other["value"]+other["size"] <= symbol["value"] or
                                    symbol["value"]+symbol["size"] <= other["value"],
                                    "separate source function ranges may not overlap")
            prior.append(symbol)
        fdes = frames.dwarf_frames(elf, isa)
        self.assertEqual({(f["code_section"], f["start"], f["size"]) for f in fdes}, extents,
                         "actual complete FDE inventory must match every source function extent")
        self.assertEqual(len(fdes), len(extents), "aliases and atomic operations create no extra function/FDE")
        self.assertTrue(all(f["cie"]["personality"] is None and f["lsda"] is None for f in fdes))
        for alias, target in aliases.items():
            a, b = function_symbols[alias], function_symbols[target]
            self.assertEqual((a["section"], a["value"], a["size"]), (b["section"], b["value"], b["size"]))
        for g in module["globals"]:
            if g["initializer"] is None: continue
            self.assertEqual(sum(s["name"] == g["name"] for s in elf.symbols), 1)
            s = elf.named[g["name"]]
            data = bytes(s["size"]) if elf.sections[s["section"]]["kind"] == 8 else \
                elf.section_data(s["section"])[s["value"]:s["value"]+s["size"]]
            self.assertEqual(data, bytes(g["initializer"]["bytes"]))
            for original in g["initializer"]["relocations"]:
                actual = elf.relocation(s["section"], s["value"]+original["offset"])
                self.assertEqual(elf.symbols[actual["symbol"]]["name"], original["symbol"])
                self.assertEqual(actual["addend"], original["addend"])
        defined_symbols = {s["name"] for s in elf.symbols if s["section"]}
        external = {s["name"] for s in elf.symbols if s["name"] and s["section"] == 0}
        self.assertFalse(any(name.startswith(("__atomic", "__sync")) for name in defined_symbols | external),
                         "inline realization must not introduce opaque atomic helpers")
        return {"object": self.bind(path), "source_function_definitions": len(defined),
                "actual_fdes": len(fdes), "aliases": aliases, "undefined_symbols": sorted(external),
                "functions": [{"name": name, "section": s["section"], "start": s["value"], "bytes": s["size"]}
                              for name, s in sorted(defined.items())]}

    def object_controls(self, original, isa, machine, module):
        data = original.read_bytes(); elf = frames.Elf(data)
        names = {f["name"] for f in module["functions"] if f["entry"] is not None}
        symbols = sorted((s for s in elf.symbols if s["name"] in names), key=lambda s: (s["section"], s["value"]))
        first, second = symbols[:2]; section = elf.sections[first["section"]]
        self.assertEqual(first["section"], second["section"]); self.assertGreater(first["size"], 1)
        cases = []
        bad = bytearray(data)
        struct.pack_into("<I", bad, second["file_offset"], struct.unpack_from("<I", data, first["file_offset"])[0])
        cases.append(("duplicate_symbol", bad, "duplicate actual function symbol records"))
        extra = next(s for s in elf.symbols if s["file_offset"] != elf.symbols[0]["file_offset"]
                     and s["info"] & 15 in (0, 3))
        bad = bytearray(data)
        struct.pack_into("<I", bad, extra["file_offset"], struct.unpack_from("<I", data, first["file_offset"])[0])
        bad[extra["file_offset"]+4] = 0  # Local STT_NOTYPE, independent of the real function record.
        cases.append(("same_name_notype", bad, "source function name requires exactly one actual named symbol record"))
        bad = bytearray(data); struct.pack_into("<Q", bad, section["header"]+8, section["flags"] & ~4)
        cases.append(("non_executable_body", bad, "function must own executable section bytes"))
        bad = bytearray(data); struct.pack_into("<Q", bad, first["file_offset"]+16, section["size"]+1)
        cases.append(("out_of_bounds_body", bad, "complete function extent must fit"))
        bad = bytearray(data); struct.pack_into("<Q", bad, second["file_offset"]+8, first["value"]+1)
        cases.append(("overlapping_bodies", bad, "separate source function ranges may not overlap"))
        frame = frames.dwarf_frames(elf, isa)[0]
        bad = bytearray(data)
        struct.pack_into("<I", bad, elf.sections[frame["section"]]["offset"]+frame["range_position"], frame["size"]+1)
        cases.append(("wrong_actual_fde_extent", bad, "actual complete FDE inventory"))
        result = []
        for label, corrupted, diagnostic in cases:
            path = original.with_name(original.name+".elf-control-"+label+".o"); path.write_bytes(corrupted)
            with self.assertRaisesRegex(AssertionError, diagnostic): self.owned_object(path, isa, machine, module)
            result.append({"case": label, "original": self.bind(original), "corrupted_copy": self.bind(path),
                           "expected_diagnostic": diagnostic, "independent_elf_audit_rejected": True})
        return result

    def link_and_run(self, isa, args, emulator, carriers, objects, tag, corrupt=False):
        binary = self.directory/(isa+"-"+tag+("-"+str(corrupt) if corrupt else ""))
        link = self.command([self.sdk/"clang", *args, "-fuse-ld=lld", "--rtlib=compiler-rt", "--unwindlib=none",
                             "-static", "-no-pie", "-Wl,--trace", "-Wl,--why-extract="+str(binary)+".extract.txt",
                             carriers[corrupt], *objects, "-o", binary])
        trace = binary.with_suffix(".link-trace.txt"); trace.write_bytes(link.stdout+link.stderr)
        selected = []
        for line in link.stdout.decode().splitlines():
            path = Path(line.split("(", 1)[0]).resolve()
            self.assertIn(str(path), self.bound, "unbound actual link provider/input: "+line)
            selected.append({"artifact": self.bound[str(path)], "trace": line})
        result = self.command(([emulator] if isa != "x86_64" else [])+[binary], success=not corrupt)
        if corrupt:
            self.assertEqual(result.returncode, 31)
            diagnostic = b"atomic mismatch check=185610" if corrupt == "concurrency" else b"atomic mismatch check=0"
            self.assertIn(diagnostic, result.stderr)
        else:
            self.assertEqual(result.stdout, golden()); self.assertEqual(result.stderr, b"")
        return {"executable": self.bind(binary), "ordered_link_trace": self.bind(trace),
                "ordered_selected_inputs": selected, "archive_extraction": self.bind(str(binary)+".extract.txt"),
                "exit_code": result.returncode, "stdout": result.stdout.decode(), "stderr": result.stderr.decode()}

    def test_whole_integer_atomic_contract_and_real_mixed_threads_all_three(self):
        emulators = self.emulators()
        reference_only = os.environ.get("OCORE_TEST_ATOMICS_REFERENCE_ONLY") == "1"
        c_source = self.directory/"whole-original.c"; c_source.write_text(C_SOURCE)
        driver = self.directory/"independent-thread-carrier.c"; driver.write_text(carrier())
        snapshot = self.directory/"test-source-snapshot.py"; snapshot.write_bytes(Path(__file__).read_bytes())
        helper_directory = self.directory/"helper-source-snapshots"; helper_directory.mkdir()
        helpers = []
        for helper in (providers, frames, weak, importer, providers.census, weak.baseline,
                       weak.promises, weak.memory, weak.native, weak.capture_qa):
            original = Path(helper.__file__).resolve()
            saved = helper_directory/(helper.__name__.replace(".", "_")+".py"); saved.write_bytes(original.read_bytes())
            self.assertEqual(self.bind(original)["sha256"], self.bind(saved)["sha256"])
            helpers.append({"module": helper.__name__, "original": self.bind(original), "snapshot": self.bind(saved)})
        tools = [self.sdk/"clang", self.sdk/"llvm-as", self.sdk/"llvm-objcopy",
                 self.sdk/"llvm-readobj", self.linker, importer.discover_library(), *emulators.values()]
        if not reference_only: tools.append(self.compiler)
        for item in [c_source, driver, snapshot, __file__, *tools]: self.bind(item)
        report = {"scope": "whole original LLVM/C atomic conformance with genuine Linux/musl pthread reference providers",
                  "atomic_execution_qualified": False, "full_rust_compiler_complete": False,
                  "provider_modules_lowered": False, "dependency_closure_complete": False,
                  "native_ostadix_qualified": False, "physical_silicon_qualified": False,
                  "weak_memory_ordering_proved": False, "lr_sc_progress_proved": False,
                  "realization_profile": PROFILE, "rv_containing_word_mapped_coherent_ram": True,
                  "rv_lr_sc_eventuality_region_required": True, "reference_only": reference_only,
                  "scripted_runtime_or_manual_provider": False, "integer_rmw_families": list(KINDS),
                  "widths": [8, 16, 32, 64], "cas_order_pairs": CAS_ORDERS,
                  "builtin_scopes": ["singlethread", "system"], "source_weakness_retained": True,
                  "weak_realization_may_be_strong": True, "thread_count": 8, "steps_per_thread": STEPS,
                  "checks_per_execution": len(list(golden_values())), "golden_stdout": golden().decode(),
                  "compiler": None if reference_only else self.bind(self.compiler), "test_source": self.bind(snapshot),
                  "helper_source_snapshots": helpers, "targets": {}, "passed": False,
                  "process_environment": {key: os.environ.get(key) for key in
                      ("PATH", "LD_LIBRARY_PATH", "OCOREC", "OCORE_TEST_LLVM22_BIN", "LD_LLD",
                       "OCORE_TEST_QEMU_AARCH64", "OCORE_TEST_QEMU_RISCV64", "OCORE_TEST_REQUIRE_ALL_ISAS",
                       "OCORE_TEST_ATOMICS_REFERENCE_ONLY")}}
        report_path = self.directory/"report.json"
        try:
            for isa, (target, _, machine, _) in TARGETS.items():
                with self.subTest(isa=isa):
                    cpp_args, _ = self.profile(isa)
                    args = [item for item in cpp_args if item not in {"-nostdlib++", "-nostdinc++", "-std=c++14", "-frtti"}]
                    args += ["-std=c11", "-D_GNU_SOURCE=1", "-pthread"]
                    if isa == "riscv64": args += ["-march=rv64gc", "-mabi=lp64d"]
                    # These fresh target headers/DataLayouts come from the
                    # genuine per-ISA frontend. No existing input is retargeted.
                    c_ll, c_bc = self.directory/(isa+"-original.ll"), self.directory/(isa+"-original.bc")
                    self.command([self.sdk/"clang", *args, "-emit-llvm", "-S", c_source, "-o", c_ll])
                    self.command([self.sdk/"clang", *args, "-emit-llvm", "-c", c_source, "-o", c_bc])
                    header = "\n".join(re.findall(r'^target (?:triple|datalayout) = .*$', c_ll.read_text(), re.M))+"\n"
                    self.assertEqual(len(header.splitlines()), 2)
                    # Raw authored LLVM must declare the same explicit target
                    # ABI as the genuine frontend. Triple/DataLayout alone do
                    # not select RV's LP64D calling/ELF profile.
                    abi_flags = re.findall(r'^(![0-9]+) = !\{i32 ([0-9]+), !"target-abi", !"([^"\n]+)"\}$',
                                           c_ll.read_text(), re.M)
                    if isa == "riscv64":
                        self.assertEqual([(behavior, abi) for _, behavior, abi in abi_flags], [("1", "lp64d")])
                    else: self.assertEqual(abi_flags, [])
                    if abi_flags:
                        identifier, behavior, abi = abi_flags[0]
                        header += '!llvm.module.flags = !{'+identifier+'}\n'
                        header += identifier+' = !{i32 '+behavior+', !"target-abi", !"'+abi+'"}\n'
                    raw_ll, raw_bc = self.directory/(isa+"-whole-atomic.ll"), self.directory/(isa+"-whole-atomic.bc")
                    body, definitions = llvm_body(); raw_ll.write_text(header+body)
                    self.command([self.sdk/"llvm-as", raw_ll, "-o", raw_bc])
                    carriers = {}
                    for corrupt in (False, True, "concurrency"):
                        obj = self.directory/(isa+"-carrier"+("-"+str(corrupt) if corrupt else "")+".o")
                        macro = "CORRUPT_CONCURRENCY" if corrupt == "concurrency" else "CORRUPT_ORACLE"
                        self.command([self.sdk/"clang", *args, *(["-D"+macro+"=1"] if corrupt else []),
                                      "-c", driver, "-o", obj])
                        self.object_identity(obj, machine); self.bind(obj); carriers[corrupt] = obj
                    rows = report["targets"].setdefault(isa, [])
                    for suffix, inputs in (("ll", (raw_ll, c_ll)), ("bc", (raw_bc, c_bc))):
                        row = {"form": suffix, "whole_original_modules": [], "executions": {},
                               "authored_raw_frontend_target_declaration": {
                                   "genuine_frontend_input": self.bind(c_ll), "exact_target_header": header,
                                   "target_abi_flags": abi_flags}}
                        rows.append(row)
                        reference_objects, own_objects = [], []
                        for original in inputs:
                            inventory, atomics = self.original_inventory(original), self.source_atomics(original)
                            if original in (raw_ll, raw_bc):
                                self.assertEqual(set(inventory["definitions"]), definitions)
                                self.assertEqual(len(definitions), 346)
                                self.assertEqual(set(inventory["globals"]), {"atomic_cold", "atomic_cold_pointer"})
                                self.assertEqual(inventory["aliases"], ["atomic_cold_alias"])
                                self.assertEqual(atomics["atomic_event_count"], 346)
                            else:
                                self.assertEqual(set(inventory["definitions"]),
                                                 {"atomic_thread_step", "c_original_atomic_contract", "c_atomic_cold_unused"})
                                self.assertEqual(atomics["parameter_counts"]["atomic_thread_step"], 16)
                                self.assertEqual(atomics["atomic_event_count"], 7)
                            item = {"input": self.bind(original), "whole_original_inventory": inventory,
                                    "independent_original_atomic_census": atomics}
                            row["whole_original_modules"].append(item)
                            obj = original.with_name(original.name+".clang.o")
                            self.command([self.sdk/"clang", *args, "-c", original, "-o", obj])
                            self.object_identity(obj, machine); self.bind(obj); reference_objects.append(obj)
                            if reference_only: continue
                            module, receipt = self.whole_module(original, target, inventory, atomics)
                            item["whole_verified_import"] = receipt
                            if original in (raw_ll, raw_bc): item["admission_controls"] = self.semantic_controls(original, target, module, atomics)
                            else:
                                step = next(f for f in module["functions"] if f["name"] == "atomic_thread_step")
                                self.assertEqual(len(step["signature"]["params"]), 16)
                            obj = original.with_name(original.name+".own.o")
                            self.command([self.compiler, original, "--input-kind", "llvm-ir", "--target", target,
                                          "--atomic-profile", PROFILE, "-o", obj])
                            self.bind(obj); own_objects.append(obj)
                            item["owned_elf_function_frames"] = self.owned_object(obj, isa, machine, module)
                            if original in (raw_ll, raw_bc): item["owned_elf_controls"] = self.object_controls(obj, isa, machine, module)
                        for tag, objects in (("reference", reference_objects), ("own", own_objects)):
                            if not objects: continue
                            for corrupt in (False, True, "concurrency"):
                                label = "_concurrency_control" if corrupt == "concurrency" else "_corrupt" if corrupt else ""
                                row["executions"][tag+label] = self.link_and_run(
                                    isa, args, emulators.get(isa), carriers, objects, suffix+"-"+tag, corrupt)
                        if own_objects:
                            # Change a COPY of one owned object, preserving the
                            # complete original object and all its cold bodies.
                            renamed = own_objects[0].with_name(own_objects[0].name+".broken-copy.o")
                            self.command([self.sdk/"llvm-objcopy", "--redefine-sym=a_8_add=a_8_add_saved", own_objects[0], renamed])
                            self.bind(renamed)
                            replacement = self.directory/(isa+"-"+suffix+"-deliberate-wrong-atomic.c")
                            replacement.write_text("unsigned long a_8_add(void*p,unsigned long v){(void)p;(void)v;return 123456UL;}\n")
                            self.bind(replacement); broken = replacement.with_suffix(".o")
                            self.command([self.sdk/"clang", *args, "-c", replacement, "-o", broken]); self.bind(broken)
                            binary = self.directory/(isa+"-"+suffix+"-deliberately-broken-own")
                            self.command([self.sdk/"clang", *args, "-fuse-ld=lld", "--rtlib=compiler-rt", "--unwindlib=none",
                                          "-static", "-no-pie", carriers[False], renamed, own_objects[1], broken, "-o", binary])
                            self.bind(binary)
                            result = self.command(([emulators[isa]] if isa != "x86_64" else [])+[binary], success=False)
                            self.assertEqual(result.returncode, 31); self.assertIn(b"atomic mismatch", result.stderr)
                            row["broken_owned_object_control"] = {"original": self.bind(own_objects[0]),
                                "renamed_copy": self.bind(renamed), "replacement_source": self.bind(replacement),
                                "replacement_object": self.bind(broken), "executable": self.bind(binary),
                                "exit_code": result.returncode, "stderr": result.stderr.decode()}
                        report_path.write_text(json.dumps(report, indent=2)+"\n")
            for item in list(self.bound.values()): self.bind(item["path"], item)
            self.assertEqual(set(report["targets"]), set(TARGETS))
            expected = {"reference", "reference_corrupt", "reference_concurrency_control"} | \
                (set() if reference_only else {"own", "own_corrupt", "own_concurrency_control"})
            self.assertTrue(all(len(rows) == 2 and all(set(row["executions"]) == expected for row in rows)
                                for rows in report["targets"].values()))
            report["atomic_execution_qualified"] = not reference_only
            report["passed"] = True
        finally:
            report["bound_inputs_providers_tools_outputs"] = list(self.bound.values())
            report["commands"] = [weak.artifact(path) for path in sorted(self.directory.glob("command-*.json"))]
            report_path.write_text(json.dumps(report, indent=2)+"\n")


if __name__ == "__main__":
    unittest.main()
