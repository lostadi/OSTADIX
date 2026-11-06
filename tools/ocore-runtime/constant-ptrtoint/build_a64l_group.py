#!/usr/bin/env python3
"""Capture the complete declared original a64l/string dependency component.

The original Makefile evaluates the full source graph and compiles its four
selected C targets unchanged. This is a finite component, not full musl/CRT.
Reference objects never substitute for O-core-generated artifact members.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import subprocess

REVISION='0784374d561435f7c787a555aeab8ede699ed298'
SOURCES=('src/misc/a64l.c','src/string/strchr.c','src/string/strchrnul.c','src/string/strlen.c')
OBJECTS=tuple('obj/'+p[:-2]+'.o'for p in SOURCES)
ISAS=('x86_64','aarch64','riscv64')

def identity(path):
 p=Path(path).resolve(strict=True);return{'path':str(p),'bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}
def write(path,value):path.write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')
def source_inventory(source):
 head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=source,text=True).strip();dirty=subprocess.check_output(['git','status','--porcelain','--untracked-files=all'],cwd=source)
 if head!=REVISION or dirty:raise ValueError('original source must remain clean at '+REVISION)
 return{'path':str(source),'revision':head,'files':[identity(source/p.decode())for p in subprocess.check_output(['git','ls-files','-z'],cwd=source).split(b'\0')if p]}
def build(args):
 source=args.source.resolve(strict=True);directory=args.build.resolve(strict=True);before=source_inventory(source)
 query=directory/'component-query.mk';query.write_text('$(info OCORE_ORIGINAL_LIBC_OBJECTS=$(LIBC_OBJS))\n.PHONY: ocore-query\nocore-query:\n\t@:\n')
 common=['make','--no-print-directory','-f',str(source/'Makefile'),'srcdir='+str(source),'ARCH='+args.isa];argv=[*common,'-f',str(query),'ocore-query'];q=subprocess.run(argv,cwd=directory,capture_output=True,check=True);(directory/'query.stdout').write_bytes(q.stdout);(directory/'query.stderr').write_bytes(q.stderr)
 entries=[line.split('=',1)[1].split()for line in q.stdout.decode().splitlines()if line.startswith('OCORE_ORIGINAL_LIBC_OBJECTS=')]
 if len(entries)!=1 or any(entries[0].count(name)!=1 for name in OBJECTS):raise ValueError('each selected component must appear exactly once in the evaluated original libc object graph')
 flags='-std=c99 -nostdinc -ffreestanding -fexcess-precision=standard -frounding-math -fno-strict-aliasing -Wa,--noexecstack';cc=shlex.quote(args.cc)+' --target='+args.isa+'-unknown-linux-musl'
 if args.isa=='riscv64':cc+=' -march=rv64gc -mabi=lp64d'
 command=[*common,'CC='+cc,'CFLAGS_C99FSE='+flags,'CFLAGS_AUTO=-O2 -fomit-frame-pointer -fno-unwind-tables -fno-asynchronous-unwind-tables -fno-stack-protector',*OBJECTS];p=subprocess.run(command,cwd=directory,capture_output=True);(directory/'make.stdout').write_bytes(p.stdout);(directory/'make.stderr').write_bytes(p.stderr)
 if p.returncode:raise subprocess.CalledProcessError(p.returncode,command,p.stdout,p.stderr)
 if source_inventory(source)!=before:raise ValueError('original source changed during build')
 write(directory/'component-build.json',{'schema':'ocore.original-musl-a64l-string-component/v1','source':before,'isa':args.isa,'helper':identity(__file__),'original_makefile':identity(source/'Makefile'),'original_object_graph':entries[0],'selection':list(OBJECTS),'query_argv':argv,'build_argv':command,'original_sources':[identity(source/p)for p in SOURCES],'reference_objects':[identity(directory/p)for p in OBJECTS],'generated_headers':[identity(directory/p)for p in ['obj/include/bits/alltypes.h','obj/include/bits/syscall.h']],'scope':'complete original selected a64l.c/strchr.c/strchrnul.c/strlen.c units and original headers/build graph; no function filtering; not full libc/CRT/OS'})
def inventory(args):
 source=args.source.resolve(strict=True);directory=args.build.resolve(strict=True);record=json.loads((directory/'component-build.json').read_bytes())
 if record['source']!=source_inventory(source)or record['isa']!=args.isa or record['helper']!=identity(__file__)or record['reference_objects']!=[identity(directory/p)for p in OBJECTS]:raise ValueError('component source/tool/build identity changed')
 write(directory/'unit-inventory.json',{'schema':'ocore-runtime-unit-inventory-v1','complete':True,'scope':record['scope'],'units':[{'id':'original-'+Path(p).stem,'kind':'clang','source':p,'role':'runtime','build_step':'build-original-a64l-string-group'}for p in SOURCES],'non_lowering_units':[],'runtime_outputs':record['reference_objects'],'component_build':identity(directory/'component-build.json')})
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=['build','inventory']);p.add_argument('--source',type=Path,required=True);p.add_argument('--build',type=Path,required=True);p.add_argument('--isa',choices=ISAS,required=True);p.add_argument('--cc',required=True);p.add_argument('--expected-helper-sha256',required=True);a=p.parse_args()
 if identity(__file__)['sha256']!=a.expected_helper_sha256:p.error('component helper differs from exact recipe pin')
 (build if a.action=='build'else inventory)(a)
if __name__=='__main__':main()
