#!/usr/bin/env python3
"""Retained CLI custody controls. Mutations affect only fresh private test copies."""
from pathlib import Path
import argparse
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import time
from unittest import mock

ROOT = Path(__file__).resolve().parent

def need(condition, message):
    if not condition:
        raise RuntimeError(message)

def pin(path):
    path = Path(path)
    data = path.read_bytes()
    return dict(path=str(path), bytes=len(data), sha256=hashlib.sha256(data).hexdigest())

def snapshot(path):
    return {p.relative_to(path).as_posix(): pin(p) for p in sorted(path.rglob('*')) if p.is_file()}

def record_command(argv, output):
    started = time.monotonic()
    child = subprocess.run(argv, capture_output=True, timeout=180)
    (output / 'stdout').write_bytes(child.stdout)
    (output / 'stderr').write_bytes(child.stderr)
    row = dict(argv=argv, exit_code=child.returncode, seconds=time.monotonic()-started,
               stdout=pin(output/'stdout'), stderr=pin(output/'stderr'))
    if (output/'result.json').exists():
        row['receipt'] = pin(output/'result.json')
    return row

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--evidence-root', required=True, type=Path)
    ap.add_argument('--output', required=True, type=Path)
    args = ap.parse_args()
    need(sys.platform == 'linux' and sys.version_info[:2] == (3, 12), 'Linux Python3.12 required')
    need(args.output.is_absolute() and args.output.parent.resolve() == args.output.parent
         and not args.output.exists() and not args.output.is_symlink(), 'fresh canonical output required')
    evidence = args.evidence_root
    need(evidence.is_absolute() and evidence.resolve() == evidence, 'canonical evidence required')
    for root in (ROOT, evidence):
        need(root != args.output and root not in args.output.parents and args.output not in root.parents,
             'test output must not overlap inputs')
    out = args.output
    out.mkdir(mode=0o700)
    report = {'schema':'ostadix.qemu-r7-launcher-tests/v1', 'ok':False, 'cases':[],
              'scope':'Actual fixed host controls and launcher custody negatives; no QEMU/build/default actions'}
    source_before = snapshot(ROOT)
    entries = json.loads((ROOT/'schema-inputs.json').read_bytes())['files']
    external_before = [pin(evidence/x['relative']) for x in entries]
    def save():
        (out/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    save()
    def clone_case(name):
        c = out/name
        c.mkdir()
        package = c/'source'
        shutil.copytree(ROOT, package)
        schemas = c/'evidence'
        schemas.mkdir()
        for row in entries:
            target = schemas/row['relative']
            target.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(evidence/row['relative'],target)
        return c,package,schemas
    def run_case(name,package,schemas,base,expected_status,expected_text):
        dest = base/'attempt'
        row = record_command([sys.executable,'-I','-B',str(package/'run-controls.py'),
                              '--evidence-root',str(schemas),'--output',str(dest)], base)
        need(row['exit_code']==expected_status, (name,row))
        doc = json.loads((dest/'result.json').read_bytes()) if (dest/'result.json').exists() else None
        if expected_status == 0:
            need(doc and doc['ok'] is True and len(doc['commands'])==3 and doc['inputs_unchanged'] is True,
                 'positive launcher did not execute all three real controls')
            need(doc['coverage']=={'recipe_synthetic_cases':14,'generator_pairs':2,
                 'own_non_QEMU_parent_death_children':1,'saved_schema_shapes':6,
                 'stream_false_guard':1,'dynamic_constructor_controls':1}, 'wrong coverage')
            need(doc['QEMU_executed'] is False and doc['emulator_or_native_FP_admitted'] is False,
                 'scope changed')
        else:
            need(doc and doc['ok'] is False and doc['commands']==[], 'preflight dispatched a driver')
            need(expected_text in doc.get('error',''), (name,doc))
        row['name']=name
        row['launcher_result']=pin(dest/'result.json') if doc else None
        row['passed']=True
        report['cases'].append(row)
        save()
    try:
        # One complete positive using the immutable real package and external inputs.
        c=out/'positive';c.mkdir()
        run_case('complete-real-host-controls',ROOT,evidence,c,0,'')
        first=entries[0]['relative']; last=entries[-1]['relative']
        for kind in ('last-schema-corrupt','schema-missing','schema-symlink','schema-hardlink',
                     'source-corrupt','source-extra','source-symlink'):
            c,package,schemas=clone_case(kind)
            if kind=='last-schema-corrupt':
                q=schemas/last;q.write_bytes(q.read_bytes()+b' ');text='schema bytes mismatch'
            elif kind=='schema-missing':
                (schemas/first).unlink();text='missing regular input'
            elif kind=='schema-symlink':
                q=schemas/first;alternate=c/'held-schema';q.rename(alternate);q.symlink_to(alternate)
                text='symlink input is unsupported'
            elif kind=='schema-hardlink':
                os.link(schemas/first,c/'owned-extra-link');text='input aliases another file'
            elif kind=='source-corrupt':
                q=package/'recipe-v2/pins.json';q.write_bytes(q.read_bytes()+b' ');text='source bytes mismatch'
            elif kind=='source-extra':
                (package/'unexpected').write_bytes(b'unlisted');text='source membership differs'
            else:
                q=package/'README.md';alternate=c/'held-readme';q.rename(alternate);q.symlink_to(alternate)
                text='symlink input is unsupported'
            run_case(kind,package,schemas,c,1,text)
        # Geometry errors must not create the requested destination or touch the package.
        for kind in ('inside-source','symlink-output-parent'):
            c,package,schemas=clone_case(kind)
            if kind=='inside-source':
                destination=package/'forbidden-output'
            else:
                alias=c/'alias';alias.symlink_to(package,target_is_directory=True)
                destination=alias/'forbidden-output'
            row=record_command([sys.executable,'-I','-B',str(package/'run-controls.py'),
                 '--evidence-root',str(schemas),'--output',str(destination)],c)
            need(row['exit_code']==2 and not destination.exists(), (kind,row))
            row.update(name=kind,passed=True,expected_status=2)
            report['cases'].append(row);save()
        # Synthetic orchestration control: intercept the fixed driver call, mutate an
        # owned package copy AFTER successful preflight, then require the postguard
        # to reject before it can consume any purported successful driver summary.
        c,package,schemas=clone_case('postguard-source-drift')
        spec=importlib.util.spec_from_file_location('private_r7_launcher',package/'run-controls.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        intercepted=[]
        def mutate_after_preflight(name,work,output,environment):
            q=package/'README.md';q.write_bytes(q.read_bytes()+b'\nowned postguard control\n')
            intercepted.append(name)
            return {'name':name,'exit_code':0,'timed_out':False,'synthetic':'no driver executed'}
        so=io.StringIO();se=io.StringIO()
        with mock.patch.object(module,'execute_driver',side_effect=mutate_after_preflight), \
                contextlib.redirect_stdout(so),contextlib.redirect_stderr(se):
            status=module.main(['--evidence-root',str(schemas),'--output',str(c/'attempt')])
        (c/'stdout').write_text(so.getvalue());(c/'stderr').write_text(se.getvalue())
        doc=json.loads((c/'attempt/result.json').read_bytes())
        need(status==1 and doc['ok'] is False and doc['inputs_unchanged'] is False
             and intercepted==['recipe-error-paths.py'] and len(doc['commands'])==1
             and 'input changed after preflight' in doc['error'], 'source postguard failed open')
        report['cases'].append({'name':'postguard-source-drift','passed':True,'exit_code':status,
            'kind':'in-process intercepted driver; no driver or child executed',
            'stdout':pin(c/'stdout'),'stderr':pin(c/'stderr'),'launcher_result':pin(c/'attempt/result.json')})
        need(len(report['cases'])==11,'expected exactly eleven controls')
        report['ok']=True
    except Exception:
        import traceback
        report['error']=traceback.format_exc()
    finally:
        report['source_before']=source_before
        report['source_after']=snapshot(ROOT)
        report['external_schemas_before']=external_before
        report['external_schemas_after']=[pin(evidence/x['relative']) for x in entries]
        report['inputs_unchanged']=(report['source_after']==source_before
            and report['external_schemas_after']==external_before)
        report['ok']=bool(report['ok'] and report['inputs_unchanged'])
        save()
    print(json.dumps({'ok':report['ok'],'cases':len(report['cases']),'result':pin(out/'result.json')}))
    return 0 if report['ok'] else 1

if __name__=='__main__':
    raise SystemExit(main())
