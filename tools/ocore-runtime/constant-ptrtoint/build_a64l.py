#!/usr/bin/env python3
"""Build the complete original musl a64l unit using its original Makefile.

This explicitly declared one-unit component does not replace a whole-libc
inventory. The original compiler's object is reference capture evidence only.
The resulting complete two-function unit retains its required strchr provider.
Original libc archive providers and test bootstrap are external reference
dependencies, never lowered implementation closure.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import subprocess

REVISION='0784374d561435f7c787a555aeab8ede699ed298'
SOURCE='src/misc/a64l.c'
OBJECT='obj/src/misc/a64l.o'
ISAS=('x86_64','aarch64','riscv64')


def identity(path):
    p=Path(path).resolve(strict=True)
    return {'path':str(p),'bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}


def write(path,value):
    path.write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')


def source_inventory(source):
    head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=source,text=True).strip()
    dirty=subprocess.check_output(['git','status','--porcelain','--untracked-files=all'],cwd=source)
    if head!=REVISION or dirty:
        raise ValueError('original musl source must stay clean at '+REVISION)
    names=subprocess.check_output(['git','ls-files','-z'],cwd=source).split(b'\0')
    return {'path':str(source),'revision':head,'files':[identity(source/name.decode()) for name in names if name]}


def build(args):
    source=args.source.resolve(strict=True);directory=args.build.resolve(strict=True)
    before=source_inventory(source)
    # Evaluate the exact original object list. The added target only prints a
    # make variable; it contributes no implementation, override or recipe body.
    query=directory/'component-query.mk'
    query.write_text('$(info OCORE_ORIGINAL_LIBC_OBJECTS=$(LIBC_OBJS))\n.PHONY: ocore-query\nocore-query:\n\t@:\n')
    common=['make','--no-print-directory','-f',str(source/'Makefile'),'srcdir='+str(source),'ARCH='+args.isa]
    argv=[*common,'-f',str(query),'ocore-query']
    q=subprocess.run(argv,cwd=directory,capture_output=True,check=True)
    (directory/'query.stdout').write_bytes(q.stdout);(directory/'query.stderr').write_bytes(q.stderr)
    entries=[line.split('=',1)[1].split() for line in q.stdout.decode().splitlines() if line.startswith('OCORE_ORIGINAL_LIBC_OBJECTS=')]
    if len(entries)!=1 or entries[0].count(OBJECT)!=1:
        raise ValueError('original evaluated libc object graph does not contain the selected a64l component exactly once')
    flags='-std=c99 -nostdinc -ffreestanding -fexcess-precision=standard -frounding-math -fno-strict-aliasing -Wa,--noexecstack'
    cc=shlex.quote(args.cc)+' --target='+args.isa+'-unknown-linux-musl'
    if args.isa=='riscv64': cc+=' -march=rv64gc -mabi=lp64d'
    # Explicit component configuration using the original Makefile variables.
    # It is distinct from the full-library configured capture; no existing
    # invocation is edited or stripped to gain importer admission.
    command=[*common,'CC='+cc,'CFLAGS_C99FSE='+flags,'CFLAGS_AUTO=-O2 -fomit-frame-pointer -fno-unwind-tables -fno-asynchronous-unwind-tables -fno-stack-protector',OBJECT]
    p=subprocess.run(command,cwd=directory,capture_output=True)
    (directory/'make.stdout').write_bytes(p.stdout);(directory/'make.stderr').write_bytes(p.stderr)
    if p.returncode: raise subprocess.CalledProcessError(p.returncode,command,p.stdout,p.stderr)
    after=source_inventory(source)
    if after!=before: raise ValueError('original source changed during component build')
    write(directory/'component-build.json',{'schema':'ocore.original-musl-a64l-component/v1','source':before,
        'isa':args.isa,'helper':identity(__file__),'original_makefile':identity(source/'Makefile'),
        'original_object_graph':entries[0],'selection':OBJECT,'query_argv':argv,'build_argv':command,
        'original_source':identity(source/SOURCE),'reference_object':identity(directory/OBJECT),
        'generated_headers':[identity(directory/p) for p in ['obj/include/bits/alltypes.h','obj/include/bits/syscall.h']],
        'platform_dependency':'unresolved strong strchr dependency; source component is not standalone libc/CRT; reference libc archive is a test-only provider',
        'scope':'complete explicitly selected unchanged a64l unit and original header/build dependency graph; not whole libc/CRT/kernel'})


def inventory(args):
    source=args.source.resolve(strict=True);directory=args.build.resolve(strict=True)
    record=json.loads((directory/'component-build.json').read_bytes())
    if record['source']!=source_inventory(source) or record['isa']!=args.isa or record['helper']!=identity(__file__) or record['reference_object']!=identity(directory/OBJECT):
        raise ValueError('original component source/build identity changed before inventory')
    write(directory/'unit-inventory.json',{'schema':'ocore-runtime-unit-inventory-v1','complete':True,
        'scope':record['scope'],'units':[{'id':'original-a64l','kind':'clang','source':SOURCE,'role':'runtime','build_step':'build-original-a64l'}],
        'non_lowering_units':[],'runtime_outputs':[record['reference_object']],'component_build':identity(directory/'component-build.json')})


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=['build','inventory']);p.add_argument('--source',type=Path,required=True);p.add_argument('--build',type=Path,required=True);p.add_argument('--isa',choices=ISAS,required=True);p.add_argument('--cc',required=True);p.add_argument('--expected-helper-sha256',required=True)
    a=p.parse_args()
    if identity(__file__)['sha256']!=a.expected_helper_sha256:p.error('component helper differs from exact recipe pin')
    (build if a.action=='build' else inventory)(a)


if __name__=='__main__':main()
