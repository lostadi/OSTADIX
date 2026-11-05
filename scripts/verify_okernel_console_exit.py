#!/usr/bin/env python3
"""Type exit and quit in two private real boots and require saved shutdown.

Second boot uses the real tmux launcher. No working/default VM is selected.
This qualifies the existing hosted Linux/original Plan9 compatibility profile.
"""
from __future__ import annotations
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pty
import secrets
import selectors
import subprocess
import sys
import tempfile
import termios
import time

from verify_okernel_unified_console import Terminal, hash_file
from verify_okernel_unified_client import checked_command, preflight

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ('scripts/verify_okernel_console_exit.py', 'scripts/okernel_unified_world.py',
           'scripts/okernel_package_domain.py', 'scripts/okernel-unified-console.sh',
           'ocore/guest/linux/package-domain/package-domain-init',
           'ocore/guest/linux/package-domain/okernel-shellrc',
           'ocore/guest/linux/package-domain/p9-controller')


def identity(path):
    path = Path(path)
    return {'path': str(path.resolve()), 'bytes': path.stat().st_size, 'sha256': hash_file(path)}


class AttachedTerminal(Terminal):
    def __init__(self, state, build, directory):
        self.master, self.slave = pty.openpty()
        self.before = termios.tcgetattr(self.slave)
        self.capture = bytearray()
        self.log = (directory / 'terminal.log').open('wb')
        def foreground():
            os.setsid()
            fcntl.ioctl(0, termios.TIOCSCTTY, 0)
        self.socket = 'ostadix-unified-' + hashlib.sha256(os.fsencode(state)).hexdigest()[:24]
        self.process = subprocess.Popen(['bash', str(ROOT / 'scripts/okernel-unified-console.sh'),
            '--state', str(state), '--build', str(build), 'start'], stdin=self.slave,
            stdout=self.slave, stderr=self.slave, preexec_fn=foreground, close_fds=True,
            env={**os.environ, 'TERM': 'xterm', 'PYTHONDONTWRITEBYTECODE': '1'})
        self.selector = selectors.DefaultSelector()
        self.selector.register(self.master, selectors.EVENT_READ)

    def wait(self, marker, timeout=180, line=False):
        # tmux emits cursor-addressed screen updates, so raw PTY line splitting
        # cannot recover complete displayed lines. Query this private server's
        # rendered scrollback rather than treating ANSI fragments as records.
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            pane = subprocess.run(['tmux', '-L', self.socket, 'capture-pane', '-p', '-J',
                '-S', '-2000', '-t', '=okernel-unified:console.0'], capture_output=True, timeout=5)
            text = pane.stdout.replace(b'\r', b'')
            if (marker in text.split(b'\n') if line else marker in text):
                (Path(self.log.name).parent / 'rendered-pane.txt').write_bytes(text)
                return
            if self.process.poll() is not None:
                raise RuntimeError('attached console exited before '+repr(marker))
            self.pump(.1)
        raise TimeoutError('missing rendered-console output '+repr(marker))

    def close(self):
        try:
            super().close()
        finally:
            # This unique server belongs solely to this explicit private fork.
            subprocess.run(['tmux', '-L', self.socket, 'kill-server'], capture_output=True, timeout=5)


def verify(state, build, output):
    before = preflight(state, build)
    state, build = Path(before['state']), Path(before['build'])
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    report = {'schema': 'ostadix.console-logout-acceptance/v1', 'ok': False,
              'scope': __doc__, 'inputs': before, 'sources': {}, 'boots': [],
              'existing_vm_actions': [], 'started': time.time()}
    receipt = output / 'result.json'
    def save():
        receipt.write_text(json.dumps(report, indent=2) + '\n')
    for name in SOURCES:
        p=ROOT/name;dest=output/'sources'/name;dest.parent.mkdir(parents=True,exist_ok=True)
        dest.write_bytes(p.read_bytes());dest.chmod(0o400)
        report['sources'][name]={'selected':identity(p),'captured':identity(dest)}
    save()
    terminal=None
    try:
        token=secrets.token_hex(8)
        for index, word in enumerate(('exit','quit')):
            directory=output/word;directory.mkdir()
            terminal=(Terminal if index==0 else AttachedTerminal)(state,build,directory)
            terminal.wait(b'Linux and original Plan 9 share this workspace.', timeout=300)
            session=Path((state/'latest-unified-session').read_text().strip())
            step={'word':word,'session':str(session),'attached_tmux':index==1}
            report['boots'].append(step);save()
            checked_command(terminal, 'test -r /usr/local/libexec/okernel-shellrc && '
                'test "$(sha256sum /usr/local/libexec/p9-controller | cut -d " " -f1)" = '+
                report['sources']['ocore/guest/linux/package-domain/p9-controller']['selected']['sha256'])
            if index==0:
                checked_command(terminal, "printf '%s\\n' "+token+" > /n/okernel/work/exit-persist-"+token)
                checked_command(terminal, 'p9 cat /n/work/exit-persist-'+token, timeout=180)
                # Nested shell logout must return to its parent, not the host.
                terminal.send(b'/bin/sh -i\n');terminal.pump(.5)
                nested='NESTED_'+token
                terminal.send(('echo '+nested+'\n').encode());terminal.wait(nested.encode(),line=True)
                terminal.send(b'exit\n');terminal.pump(.5)
                checked_command(terminal, 'echo OUTER_SURVIVED_'+token)
                # Literal exit read by a foreground program must remain data.
                foreground='FOREGROUND_READY_'+token
                terminal.send(("( printf '%s\\n' "+foreground+"; IFS= read -r text; printf '%s\\n' \"$text\" > /tmp/exit-input )\n").encode())
                terminal.wait(foreground.encode(), line=True)
                terminal.send(b'exit\n')
                checked_command(terminal, "test \"$(cat /tmp/exit-input)\" = exit")
            else:
                checked_command(terminal, 'test "$(cat /n/okernel/work/exit-persist-'+token+')" = '+token)
            terminal.send((word+'\n').encode())
            deadline=time.monotonic()+180
            while terminal.process.poll() is None and time.monotonic()<deadline:
                terminal.pump(.1)
            if terminal.process.poll() is None:
                raise TimeoutError(word+' did not return to the host after paired save')
            terminal.pump()
            if terminal.process.returncode!=0:
                raise RuntimeError(word+' returned host status '+str(terminal.process.returncode))
            if termios.tcgetattr(terminal.slave)!=terminal.before:
                raise RuntimeError(word+' did not restore host terminal attributes')
            record=json.loads((session/'result.json').read_bytes())
            head=json.loads((state/'head.json').read_bytes())
            if (record.get('ok') is not True or record.get('after')!=head or
                any(record.get(k) is not True for k in ('paired_snapshot','virtual_cpu_stopped','native_operations_quiescent'))):
                raise RuntimeError(word+' lacks confirmed saved pair')
            events=record.get('console_exit_requests',[])
            if len(events)!=1 or events[0]['request_id'] not in head.get('console_exit_consumed',[]):
                raise RuntimeError(word+' lacks one consumed protected logout event')
            if index==1:
                check=subprocess.run(['tmux','-L',terminal.socket,'has-session','-t','=okernel-unified'],capture_output=True)
                if check.returncode==0:
                    raise RuntimeError('successful tmux console stayed open')
            step.update(ok=True,paired_save=identity(session/'result.json'),head=head,
                        console_exit_request=events[0],terminal_restored=True,host_exit=terminal.process.returncode)
            terminal.close();terminal=None;save()
        if report['boots'][0]['console_exit_request']['request_id']==report['boots'][1]['console_exit_request']['request_id']:
            raise RuntimeError('second boot reused logout identity')
        for name,entry in report['sources'].items():
            if identity(ROOT/name)!=entry['selected']:
                raise RuntimeError('source changed during qualification: '+name)
        report.update(ok=True,finished=time.time(),checks=[
            'typed exit and quit each return to host status0 after a confirmed paired save',
            'real tmux successful pane closes and host tty attributes restore',
            'nested shell exit and foreground literal exit do not close the managed console',
            'ordinary original Plan9 read shares the Linux native file',
            'restart restores file and admits a fresh logout identity'])
    except BaseException as error:
        report['error']=type(error).__name__+': '+str(error)
        raise
    finally:
        if terminal is not None:terminal.close()
        save()
    return report


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state',type=Path,required=True)
    parser.add_argument('--build',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    a=parser.parse_args()
    try:
        verify(a.state,a.build,a.output)
    except (OSError,ValueError,RuntimeError,TimeoutError,subprocess.SubprocessError) as error:
        print('Console logout acceptance: FAIL: '+str(error),file=sys.stderr);return 1
    print('Console logout acceptance: PASS\nEvidence: '+str(a.output/'result.json'));return 0

if __name__=='__main__':raise SystemExit(main())
