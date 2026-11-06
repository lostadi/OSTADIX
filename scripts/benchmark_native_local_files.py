#!/usr/bin/env python3
"""Measure actual native common-file backends in one matched hosted profile.

Preserves the unchanged pre-local wire baseline and compares candidate wire vs
candidate local using the same production service code, fresh full trusted
initialization, bytes, transaction granularity and warmup. This is a component
measurement; no Linuxmemfd, physical-hardware or whole-system efficiency claim.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import tempfile
import time

ROOT=Path(__file__).resolve().parents[1]

def identity(path):
    path=Path(path);h=hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda:stream.read(1048576),b''):h.update(block)
    return {'path':str(path.resolve()),'bytes':path.stat().st_size,'sha256':h.hexdigest()}


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--compiler',type=Path,required=True)
    p.add_argument('--codec-manifest',type=Path,required=True)
    p.add_argument('--arm-codec-manifest',type=Path,required=True)
    p.add_argument('--repeats',type=int,default=5)
    args=p.parse_args(argv)
    output=args.output.resolve();output.mkdir(parents=True,exist_ok=False)
    result={'schema':'ostadix.native-local-three-profile-cost/v1','ok':False,'scope':'Hosted native common-file component only; no full OS, original application, allISA, physical hardware or system efficiency claim','commands':[],'records':[]}
    paths=[ROOT/'ocore/runtime/common'/x for x in ['namespace_store.oc','posix_namespace_files.oc','u9fs_codec.oc']]+[ROOT/'tests/test_native_local_namespace_files.py',Path(__file__)]
    try:
        if platform.system()!='Linux' or platform.machine()!='x86_64':raise RuntimeError('requires actual matching Linux x86-64 host; foreign machine code is never executed')
        if args.repeats<=0:raise ValueError('repeats must be positive')
        before=[identity(x)for x in paths];result['source_before']=before;result['compiler']=identity(args.compiler)
        result['codec_manifests']=[identity(args.codec_manifest),identity(args.arm_codec_manifest)]
        os.environ.update(OCOREC_BIN=str(args.compiler.resolve()),OCORE_U9FS_MANIFEST=str(args.codec_manifest.resolve()),OCORE_U9FS_ARM_MANIFEST=str(args.arm_codec_manifest.resolve()))
        tempfile.tempdir=str(output);sys.path.insert(0,str(ROOT))
        module=importlib.import_module('tests.test_native_local_namespace_files');module.NativeLocalNamespaceFilesTests.setUpClass();fixture=module.NativeLocalNamespaceFilesTests.output
        result['fixture']=str(fixture);result['build_commands']=module.NativeLocalNamespaceFilesTests.commands
        source=module.common_harness();start=source.index('static void benchmark(');end=source.index('static void binary_sizes(',start);body=source[start:end]
        old='int local=!strcmp(argv[2],"local"),writing=!strcmp(argv[3],"write");'
        assert body.count(old)==1
        body=body.replace(old,'int local=!strcmp(argv[2],"local"),current=strcmp(argv[2],"wire")!=0,writing=!strcmp(argv[3],"write");uint64_t generation=current?2:1;assert(!strcmp(argv[2],"wire")||!strcmp(argv[2],"candidate-wire")||local);')
        old='create_file("benchmark",payload,bytes);int64_t fd=open_("/work/benchmark",2,0);assert(fd==3);'
        assert body.count(old)==1
        body=body.replace(old,old+'\n if(current){assert(FN(init_backend)(2,local?1:0)==0&&FN(provision)(11,21,2)==0);fd=FN(open_file)(11,21,2,(const uint8_t*)"/work/benchmark",15,2,0);assert(fd==3);}')
        body=body.replace('=local?FN(', '=current?FN(').replace('(11,21,1,fd,','(11,21,generation,fd,')
        body=body.replace('local?"local":"wire",writing?', 'argv[2],writing?')
        source=source[:start]+body+source[end:]
        c=output/'three-profile.c';c.write_text(source);binary=output/'three-profile'
        build=['clang','-O2','-no-pie','-I',str(fixture/'headers'),str(c),str(fixture/'inspectable.o'),'-o',str(binary)]
        built=subprocess.run(build,capture_output=True,text=True,timeout=120);(output/'fixture-build.log').write_text(built.stdout+built.stderr)
        result['commands'].append({'argv':build,'exit_code':built.returncode})
        if built.returncode:raise RuntimeError('C measurement fixture failed: '+built.stderr)
        result['measurement_source']=identity(c);result['measurement_binary']=identity(binary);result['profile']={'backing_volume_bytes':16777216,'transaction_bytes':8168,'warmups':3,'timer':'CLOCK_MONOTONIC_RAW','timed_operation':'seek to0 then read or write; read includes byte-equality check','buffer_scope':'trusted native allocations; no usercopy aperture or host file syscall in timed region','candidate_profiles':'same compiled common service, full init generation2 and context generation2; only trusted backend differs','old_wire_profile':'exact independently captured pre-local service, generation1; retained baseline, not substituted for same-code comparison'}
        affinity={max(os.sched_getaffinity(0))};result['affinity_cpu']=next(iter(affinity));result['load_before']=os.getloadavg()
        profiles=['wire','candidate-wire','local']
        for repeat in range(args.repeats):
            for operation in ['read','write']:
                for amount,iterations in [(0,30000),(4096,700),(65536,90),(1048576,9)]:
                    for backend in profiles[repeat%3:]+profiles[:repeat%3]:
                        command=[str(binary),'bench',backend,operation,str(amount),str(iterations)];started=time.monotonic()
                        measured=subprocess.run(command,capture_output=True,text=True,timeout=120,preexec_fn=lambda:os.sched_setaffinity(0,affinity))
                        log=output/(f'{repeat}-{operation}-{amount}-{backend}.log');log.write_text(measured.stdout+measured.stderr)
                        entry={'argv':command,'exit_code':measured.returncode,'seconds':time.monotonic()-started,'log':identity(log)};result['commands'].append(entry)
                        if measured.returncode:raise RuntimeError('measurement failed: '+measured.stderr)
                        row=json.loads(measured.stdout);row.update(repeat=repeat,ns_per_operation=row['elapsed_ns']/iterations)
                        if backend=='local'and(row['codec_encodes']or row['codec_decodes']):raise RuntimeError('local profile invoked codec')
                        result['records'].append(row)
            print('three-profile benchmark round',repeat+1,'complete',flush=True)
        result['load_after']=os.getloadavg();summaries=[]
        for operation in ['read','write']:
            for amount in [0,4096,65536,1048576]:
                values={b:[r['ns_per_operation']for r in result['records']if r['backend']==b and r['operation']==operation and r['bytes']==amount]for b in profiles};medians={b:statistics.median(v)for b,v in values.items()}
                summaries.append({'operation':operation,'bytes':amount,'median_ns':medians,'candidate_wire_over_local':medians['candidate-wire']/medians['local'],'old_wire_over_local':medians['wire']/medians['local'],'samples_ns':values})
        result['summaries']=summaries;after=[identity(x)for x in paths];result['source_after']=after;result['source_stable']=before==after
        if before!=after:raise RuntimeError('native source changed during measurement')
        result['limits']=['Host common-service micro-costs only; not measurements on target bare metal or CPL3.','Codec counters measure real operations; they are not total memory-copy counts. This trusted-buffer profile has zero checked user-copy calls in all variants.','Code footprint and hardware boundary checks are separate records. Zero-length tiny ratios should not be treated as general improvements.']
        result['ok']=True
    except Exception as error:
        result['error']=str(error)
    (output/'result.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    print(json.dumps({'ok':result['ok'],'result':str(output/'result.json'),'error':result.get('error')}),flush=True)
    return 0 if result['ok']else 1

if __name__=='__main__':raise SystemExit(main())
