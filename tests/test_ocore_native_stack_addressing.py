"""Execute compact and fallback native spill addressing across all three ISAs.

The native-IR fixture forces live values on both sides of the short displacement
windows, while a separately compiled C carrier supplies the result oracle and
stack arguments. No compiler build, source import, or host libc is involved.
"""
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import unittest

from tests import test_ocore_native_import_backend as baseline


def stack_chain(huge=False):
    value, integer, instruction = baseline.value, baseline.integer, baseline.instruction
    i64, ptr = baseline.I64, baseline.PTR
    operations = []
    previous = value(0)
    # Each result occupies eight bytes in the current emitter. This crosses
    # AArch64 -256/-4095 and RV64 -2048 without assuming compact addresses in
    # the oracle. Small and fallback slots must coexist in one live frame.
    for index in range(1, 601):
        operations.append(instruction(index, i64, {
            'op': 'binary', 'kind': 'xor', 'lhs': previous,
            'rhs': integer(i64, index * 2654435761), 'flags': []}))
        previous = value(index)
    operations.extend([
        instruction(601, ptr, {'op': 'alloca', 'size': (1 << 31) + 4096 if huge else 8192,
                               'alignment': 16}),
        instruction(602, ptr, {'op': 'gep', 'base': value(601),
                               'offset': integer(i64, 8184), 'inbounds': True}),
        {'result': None, 'operation': {'op': 'store', 'pointer': value(601),
                                       'value': value(0), 'alignment': 8, 'volatile': True}},
        {'result': None, 'operation': {'op': 'store', 'pointer': value(602),
                                       'value': previous, 'alignment': 8, 'volatile': True}},
        instruction(603, i64, {'op': 'load', 'pointer': value(601), 'alignment': 8, 'volatile': True}),
        instruction(604, i64, {'op': 'load', 'pointer': value(602), 'alignment': 8, 'volatile': True}),
        instruction(605, i64, {'op': 'binary', 'kind': 'add', 'lhs': value(603),
                               'rhs': value(604), 'flags': []}),
    ])
    return baseline.function('stack_chain', operations, value(605), (i64,))


def carrier():
    params12 = ','.join(f'u64 p{i}' for i in range(12))
    params600 = ','.join(f'u64 p{i}' for i in range(600))
    return f'''
typedef unsigned long long u64;
typedef long long i64;
u64 foreign_sum({params12}) {{ return {'+'.join(f'{i+1}ULL*p{i}' for i in range(12))}; }}
u64 foreign_600({params600}) {{ return {'+'.join(f'{i+1}ULL*p{i}' for i in range(600))}; }}
extern u64 many({params12});
extern u64 forward_direct(u64);
extern u64 forward_indirect(u64 (*)({','.join(['u64']*12)}),u64);
extern signed char signed_byte(signed char);
extern u64 nested_byte(u64);
extern unsigned int unsigned_word(void);
extern unsigned int c_unsigned_word(void);
extern u64 stack_test(u64);
extern u64 forward_600(u64);
extern u64 stack_chain(u64);
static int check(void) {{
    u64 state=0x9e3779b97f4a7c15ULL;
    for (unsigned i=0;i<256;i++) {{
        state^=state<<13; state^=state>>7; state^=state<<17;
        if(many(state,2,3,4,5,6,7,8,9,10,11,12)!=state+649) return 1;
        if(forward_direct(state)!=state+649) return 2;
        if(forward_indirect(foreign_sum,state)!=state+649) return 3;
        if(signed_byte((signed char)state)!=(signed char)state) return 4;
        if(nested_byte(state)!=(u64)(i64)(signed char)state) return 5;
#if defined(__riscv)
        // RV64 C returns unsigned int sign-extended; the separate retained
        // LLVM zeroext fixture is intentionally not that C calling contract.
        if(c_unsigned_word()!=0xffffffffU) return 6;
#else
        if(unsigned_word()!=0xffffffffU) return 6;
#endif
        if(stack_test(state)!=(state^(state+1))) return 7;
        if(forward_600(state)!=state+72180099ULL) return 8;
        u64 expected=state;
        for (u64 j=1;j<=600;j++) expected^=j*2654435761ULL;
        if(stack_chain(state)!=state+expected) return 9;
    }}
    return 0;
}}
__attribute__((noreturn)) void _start(void) {{
    int status=check();
#if defined(__x86_64__)
    __asm__ volatile("syscall" : : "a"(60L), "D"((long)status) : "rcx", "r11", "memory");
#elif defined(__aarch64__)
    register long code __asm__("x0")=status;
    register long number __asm__("x8")=93;
    __asm__ volatile("svc #0" : : "r"(code), "r"(number) : "memory");
#elif defined(__riscv)
    register long code __asm__("a0")=status;
    register long number __asm__("a7")=93;
    __asm__ volatile("ecall" : : "r"(code), "r"(number) : "memory");
#endif
    __builtin_unreachable();
}}
'''


class NativeStackAddressingTests(unittest.TestCase):
    def test_short_and_large_displacements_preserve_native_abi_on_all_targets(self):
        compiler = Path(os.environ.get('OCOREC', str(baseline.ROOT / 'target/debug/ocorec')))
        clang = shutil.which('clang')
        if not compiler.is_file() or clang is None:
            self.skipTest('already-built ocorec and Clang are required')
        retained = os.environ.get('OCORE_STACK_ADDRESS_RETAIN')
        if retained:
            Path(retained).mkdir(parents=True, exist_ok=True)
            directory = Path(tempfile.mkdtemp(prefix='run-', dir=retained))
        else:
            temporary = tempfile.TemporaryDirectory(prefix='ocore-stack-address-')
            self.addCleanup(temporary.cleanup)
            directory = Path(temporary.name)
        commands = []

        def run(argv):
            result = subprocess.run([str(item) for item in argv], capture_output=True,
                                    text=True, timeout=120)
            commands.append({'argv': [str(item) for item in argv], 'returncode': result.returncode,
                             'stdout': result.stdout, 'stderr': result.stderr})
            (directory / 'commands.json').write_text(json.dumps(commands, indent=2)+'\n')
            self.assertEqual(result.returncode, 0, result.stdout+result.stderr)

        source = directory / 'carrier.c'
        source.write_text(carrier())
        host = {'AMD64': 'x86_64', 'arm64': 'aarch64'}.get(platform.machine(), platform.machine())
        for isa, target in baseline.TARGETS.items():
            with self.subTest(isa=isa):
                functions = baseline.scalar_abi_functions()+[stack_chain()]
                native = directory / (isa+'.native.json')
                native.write_text(json.dumps(baseline.module(isa, functions)))
                obj = directory / (isa+'.o')
                run([compiler, native, '--input-kind', 'native-ir', '--target', target,
                     '--emit', 'obj', '--keep-asm', '-o', obj])
                binary = directory / isa
                flags = ['-march=rv64gc', '-mabi=lp64', '-msmall-data-limit=0'] if isa=='riscv64' else []
                run([clang, '--target='+isa+'-unknown-linux-gnu', *flags, '-O1', '-ffreestanding',
                     '-fno-builtin', '-fno-stack-protector', '-fno-pic', '-fno-pie',
                     '-fno-unwind-tables', '-fno-asynchronous-unwind-tables', '-nostdlib',
                     '-static', '-fuse-ld=lld', '-Wl,--no-relax', '-Wl,-e,_start', source, obj, '-o', binary])
                runner = [] if isa==host else [shutil.which('qemu-'+isa)]
                self.assertNotIn(None, runner, 'actual qemu-'+isa+' required for execution')
                run([*runner, binary])
                # Validate the full-width offset fallback still assembles.
                # This allocation intentionally exceeds x86 disp32 and is not
                # executed or claimed as available runtime memory.
                large = directory / (isa+'-large.native.json')
                large.write_text(json.dumps(baseline.module(isa, [stack_chain(huge=True)])))
                run([compiler, large, '--input-kind', 'native-ir', '--target', target,
                     '--emit', 'obj', '-o', directory / (isa+'-large.o')])


if __name__ == '__main__':
    unittest.main()
