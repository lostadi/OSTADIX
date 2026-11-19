#!/usr/bin/env python3
"""Execute the three lifecycle constructors and crossed-domain negatives."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys

from check_ocore_native_equivalence import (ROOT, TARGETS, TARGET_CATALOG,
    RunEvidence, canonical_target_coverage, elf, execution_prefix, produce, tool)


class IdentityEvidence(RunEvidence):
    def __init__(self, directory: Path, *args, **kwargs):
        self.directory = directory
        super().__init__(*args, **kwargs)

    def run(self, *args, **kwargs):
        try:
            return super().run(*args, **kwargs)
        finally:
            partial = {"complete": False, "sources": self.sources,
                       "tools": self.tools, "environment": self.environment_record,
                       "commands": self.commands}
            (self.directory / "commands.json").write_text(json.dumps(partial, indent=2) + "\n")


def check(compiler_path: str, directory: Path) -> dict:
    catalog=canonical_target_coverage()
    compiler=tool(compiler_path,'ocorec')
    clang=tool('clang','Clang assembler/frontend')
    linker=tool('ld.lld','LLVM linker')
    owner=ROOT/'ocore/runtime/common/lifecycle_identity.oc'
    fixture=ROOT/'tests/fixtures/ocore_lifecycle_identity.oc'
    carrier=ROOT/'tests/fixtures/ocore_lifecycle_identity.c'
    evidence=IdentityEvidence(directory, [__file__,owner,fixture,carrier,TARGET_CATALOG],
                         {'ocorec':compiler,'clang':clang,'linker':linker})
    report={'schema':'ostadix.lifecycle-identity-execution/v1','backend_catalog':catalog,'targets':{}}
    for isa,(native,hosted,machine,flags) in TARGETS.items():
        prefix=execution_prefix(isa)
        obj=directory/(isa+'.o')
        produce([compiler,str(owner),str(fixture),'--target',native,'--emit','obj','--keep-asm','--function-sections','-o',str(obj)],
                [obj,obj.with_suffix('.s')],runner=evidence.checked_run)
        elf(obj,machine,1)
        executable=directory/(isa+'.elf')
        produce([clang,'--target='+hosted,*flags,'-O2','-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-pic','-nostdlib','-static','--ld-path='+linker,'-Wl,-e,_start','-Wl,--build-id=none',str(carrier),str(obj),'-o',str(executable)],
                [executable],runner=evidence.checked_run)
        elf(executable,machine,2)
        result=evidence.checked_run([*prefix,str(executable)])
        if result.stdout!=b'OCORE-LIFECYCLE-IDENTITY cases=64\n':
            raise RuntimeError('invalid identity execution output: '+repr(result.stdout))
        negatives=[]
        for label,actual,expected in [('transport-as-domain','NamespaceTransportEpoch','O10DomainGeneration'),
                                      ('session-as-transport','NamespaceSessionEpoch','NamespaceTransportEpoch')]:
            source=directory/(isa+'-'+label+'.oc')
            source.write_text('module crossed_identity;\nuse runtime::common::lifecycle_identity::'+actual+';\nuse runtime::common::lifecycle_identity::'+expected+';\nfn consume(value: '+expected+') -> void {}\nfn bad(value: '+actual+') -> void { consume(value); }\n')
            evidence.watch_source(source)
            rejected=evidence.run([compiler,str(owner),str(source),'--target',native,'--emit','mir','-o',str(source.with_suffix('.mir'))])
            diagnostic = ('expected `runtime::common::lifecycle_identity::'+expected+
                          '`, found `runtime::common::lifecycle_identity::'+actual+'`').encode()
            if rejected.returncode==0 or diagnostic not in rejected.stderr:
                raise RuntimeError('crossed identity did not produce its required type error: '+rejected.stderr.decode(errors='replace'))
            negatives.append(label)
        report['targets'][isa]={'executed':True,'cases':64,'crossed_domains_rejected':negatives,'execution_prefix':prefix}
    report['evidence']=evidence.finish()
    report['complete']=True
    return report


def main() -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ocorec',required=True)
    parser.add_argument('--output-dir',type=Path,required=True)
    args=parser.parse_args()
    try:
        args.output_dir.mkdir(parents=True,exist_ok=False)
        report=check(args.ocorec,args.output_dir)
        (args.output_dir/'identity.json').write_text(json.dumps(report,indent=2)+'\n')
        print(json.dumps({'complete':True,'targets':list(report['targets']),'cases_per_target':64}))
        return 0
    except (OSError,RuntimeError) as error:
        print(str(error),file=sys.stderr)
        return 1


if __name__=='__main__':
    raise SystemExit(main())
