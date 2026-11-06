"""Linux-user platform interfaces cannot silently bind to the native monitor."""
import importlib.util
import json
from pathlib import Path
import struct
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('kernel_platform_admission',ROOT/'scripts/okernel_native_codec.py')
codec=importlib.util.module_from_spec(spec);spec.loader.exec_module(codec)


def object_with_note(name=b'Ocore\0',payload=b'{}'):
    note=struct.pack('<III',len(name),len(payload),1)+name
    note+=bytes((-len(note))%4);note+=payload;note+=bytes((-len(note))%4)
    data=bytearray(64+64*2)+note
    data[:7]=b'\x7fELF\x02\x01\x01';struct.pack_into('<HH',data,16,1,62)
    struct.pack_into('<Q',data,40,64);struct.pack_into('<HHH',data,58,64,2,0)
    struct.pack_into('<IIQQQQIIQQ',data,128,0,7,2,0,192,len(note),0,0,4,0)
    return bytes(data)


class LinuxPlatformCustodyTests(unittest.TestCase):
    def test_kernel_rejects_user_interfaces_in_all_record_and_embedded_ir_positions(self):
        records=[{'linux_syscall_profile':'linux_user_raw_v1'},
                 {'units':[{'object_inventory':{'required_platform_interfaces':[{'schema':'ocore.linux-provider-requirement/v1'}]}}]},
                 {'symbol_inventory':{'required_platform_interfaces':[{'invented':'unknown shape still fails closed'}]}},
                 {'modules':[{'native_ir':json.dumps({'format':'ocore-native-module-v1','target':{'linux_syscall_profile':'linux_user_raw_v1'}})}]},
                 {'modules':[{'native_ir':json.dumps({'format':'ocore-native-module-v1','functions':[{'blocks':[{'instructions':[{'operation':{'op':'linux_syscall'}}]}]}]})}]},
                 {'modules':[{'native_ir':'malformed JSON'}]}, {'required_platform_interfaces':None}, {'required_platform_interfaces':{}}, {'modules':[{'native_ir':'null'}]}]
        for record in records:
            with self.subTest(record=record),self.assertRaisesRegex(ValueError,'platform|inspected'):
                codec.require_kernel_platform_record(record)

    def test_linux_triple_alone_and_platform_free_old_components_remain_admissible(self):
        codec.require_kernel_platform_record({'target':{'triple':'aarch64-unknown-linux-musl'},'symbol_inventory':{'closed':True},'modules':[{'native_ir':json.dumps({'format':'ocore-native-module-v1','target':{'triple':'x86_64-unknown-linux-musl'}})}]})
        codec.require_kernel_platform_record({'linux_syscall_profile':None,'required_platform_interfaces':[]})

    def test_kernel_rejects_exact_allocated_platform_note_even_zero_elf_undefined_symbols(self):
        with self.assertRaisesRegex(ValueError,'userspace platform object'):
            codec.require_kernel_platform_object(object_with_note())
        codec.require_kernel_platform_object(object_with_note(b'GNU\0',b'other note'))

    def test_extended_section_numbering_cannot_hide_a_userspace_platform_note(self):
        data=bytearray(object_with_note())
        struct.pack_into('<H',data,60,0)
        struct.pack_into('<Q',data,64+32,2)
        with self.assertRaisesRegex(ValueError,'userspace platform object'):
            codec.require_kernel_platform_object(bytes(data))
        for real_count in [0,2**64-1]:
            struct.pack_into('<Q',data,64+32,real_count)
            with self.assertRaisesRegex(ValueError,'extended|geometry'):
                codec.require_kernel_platform_object(bytes(data))

    def test_note_malformed_geometry_rejects_before_link(self):
        for data in [object_with_note()[:-1],object_with_note()[:140],bytes(bytearray(b'\x7fELF\x02\x01\x01')+bytearray(57))]:
            with self.subTest(size=len(data)),self.assertRaisesRegex(ValueError,'geometry|extent|exceeds'):
                codec.require_kernel_platform_object(data)


if __name__=='__main__':unittest.main()
