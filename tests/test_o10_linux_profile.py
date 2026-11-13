"""Independent newc and immutable Linux replacement profile checks."""
import importlib.util
import json
import hashlib
from pathlib import Path
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
BUILDER=load("linux_profile_builder","scripts/build_okernel_unified_world.py")
RUNNER=load("linux_profile_runner","scripts/okernel_unified_world.py")


def archive(entries):
    result=bytearray()
    for number,(name,mode,body) in enumerate([*entries,("TRAILER!!!",0,b"")],1):
        encoded=name.encode()+bytes([0])
        values=[number,mode,0,0,1,0,len(body),0,0,0,0,len(encoded),0]
        result+=b"070701"+"".join(f"{value:08x}" for value in values).encode()+encoded
        result+=bytes(-len(result)%4);result+=body;result+=bytes(-len(result)%4)
    result+=bytes(-len(result)%512)
    return bytes(result)


def parse(data):
    result=[];offset=0
    while True:
        h=data[offset:offset+110]
        if len(h)!=110 or h[:6]!=b"070701":raise ValueError("newc")
        fields=[int(h[6+i*8:14+i*8],16) for i in range(13)]
        name=data[offset+110:offset+110+fields[11]-1].decode()
        start=(offset+110+fields[11]+3)&~3;end=start+fields[6]
        result.append((name,fields,data[start:end]))
        offset=(end+3)&~3
        if name=="TRAILER!!!":return result


def fixture_initramfs():
    return archive([("init",0o100755,(ROOT/"ocore/guest/linux/package-domain/init").read_bytes()),
                    ("unchanged",0o100640,b"independent archive content")])


class LinuxProfileTests(unittest.TestCase):
    def test_deterministic_overlay_preserves_modes_content_and_source(self):
        original=fixture_initramfs();saved=bytes(original)
        template=(ROOT/"ocore/guest/linux/package-domain/init").read_bytes()
        first,recipe=BUILDER.derive_linux_initramfs(original,template)
        second,recipe2=BUILDER.derive_linux_initramfs(original,template)
        self.assertEqual((first,recipe),(second,recipe2));self.assertEqual(original,saved)
        before=parse(original);after=parse(first)
        self.assertEqual([r[0] for r in before],[r[0] for r in after])
        for left,right in zip(before,after):
            self.assertEqual(left[1][1],right[1][1])
            if left[0]!="init":self.assertEqual(left,right)
        body=after[0][2]
        self.assertIn(b"version=9p2000.u",body)
        self.assertLess(body.index(b"mount -t tmpfs tmpfs /newroot/run"),body.index(b"mount --move /dev"))
        self.assertLess(body.index(b"mount --bind /newroot/run/o10-pkg-namespace"),body.index(b"exec switch_root"))
        self.assertIn(b"mount -o remount,bind,ro",body)
        self.assertNotIn(b"sed -i",body)
        self.assertEqual(recipe["changed_entries"],["init"]);self.assertFalse(recipe["disk_script_modified"])

    def test_unexpected_init_or_archive_is_an_explicit_failure(self):
        template=(ROOT/"ocore/guest/linux/package-domain/init").read_bytes()
        cases=[b"not newc",archive([("init",0o100644,template)]),
               archive([("init",0o100755,template+b"unexpected")]),
               archive([("init",0o100755,template),("init",0o100755,template)]),
               archive([("other",0o100755,template)])]
        for case in cases:
            with self.subTest(bytes=len(case)),self.assertRaises(ValueError):
                BUILDER.derive_linux_initramfs(case,template)
        with self.assertRaisesRegex(ValueError,"layout"):
            BUILDER.derive_linux_initramfs(archive([("init",0o100755,b"bad")]),b"bad")

    def test_malformed_newc_sizes_names_and_trailer_are_rejected(self):
        template=(ROOT/"ocore/guest/linux/package-domain/init").read_bytes()
        valid=fixture_initramfs()
        corrupt=[]
        header=bytearray(valid);header[6:14]=b"not-hex!";corrupt.append(bytes(header))
        header=bytearray(valid);header[94:102]=b"00000000";corrupt.append(bytes(header))
        header=bytearray(valid);header[94:102]=b"ffffffff";corrupt.append(bytes(header))
        header=bytearray(valid);header[114]=1;corrupt.append(bytes(header))
        header=bytearray(valid);header[54:62]=b"ffffffff";corrupt.append(bytes(header))
        corrupt.extend([valid[:109],valid+b"unexpected nonzero trailing data"])
        for name in ("./init", "/init", "directory/../init", "init"+chr(0)+"suffix"):
            corrupt.append(archive([("init",0o100755,template),(name,0o100755,b"alias")]))
        for case in corrupt:
            with self.subTest(bytes=len(case)),self.assertRaises(ValueError):
                BUILDER.derive_linux_initramfs(case,template)

    def test_copy_bounds_and_boot_metadata_are_not_guest_or_survivor_ram(self):
        contract=BUILDER.linux_recovery_contract(0x7e00000,0x10000,0x8000000)
        self.assertEqual(contract,RUNNER.LINUX_RECOVERY)
        forbidden=[(0x40000000,0x41000000),(0x48000000,0x68000000),(0x6c000000,0xb0000000),
                   (0xb0000000,0xd0000000),(0xd0000000,0xd1000000),(0xd1000000,0xd1010000)]
        windows=[(contract[k+"_backup_address"],contract[k+"_backup_address"]+contract[k+"_max_bytes"])
                 for k in ("kernel","dtb","initrd")]
        for start,end in windows:
            self.assertLessEqual(end,0x100000000)
            for low,high in forbidden:self.assertFalse(start<high and low<end)
        for index,(start,end) in enumerate(windows):
            for low,high in windows[index+1:]:self.assertFalse(start<high and low<end)
        for sizes in [(0,1,1),(0x7e00001,1,1),(1,0x10001,1),(1,1,0x8000001)]:
            with self.assertRaises(ValueError):BUILDER.linux_recovery_contract(*sizes)

    def test_immutable_copies_match_all_three_boot_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);files={}
            for backup,original in [("inputs/linux-recovery.Image","inputs/linux.Image"),
                                    ("inputs/linux-recovery.dtb","linux.dtb"),
                                    ("inputs/linux-recovery.initramfs","inputs/linux.initramfs")]:
                for name in (backup,original):
                    path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(original.encode());files[name]=path
            RUNNER.validate_linux_recovery_inputs(files)
            files["inputs/linux-recovery.dtb"].write_bytes(b"wrong")
            with self.assertRaisesRegex(ValueError,"differs"):RUNNER.validate_linux_recovery_inputs(files)


    def test_original_initramfs_identity_rejects_non_init_payload_tampering(self):
        original=fixture_initramfs()
        tampered=original.replace(b"independent archive content",b"Independent archive content")
        self.assertNotEqual(original,tampered);self.assertEqual(len(original),len(tampered))
        template=(ROOT/"ocore/guest/linux/package-domain/init").read_bytes()
        # Derivation preserves other entries; identity admission must reject
        # corruption outside /init before that transform or any publication.
        derived,_=BUILDER.derive_linux_initramfs(tampered,template)
        self.assertIn(b"Independent archive content",derived)
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory);payload=base/"payload";payload.mkdir()
            (payload/"Image").write_bytes(b"original Linux image fixture")
            (payload/"linux.config").write_text("CONFIG_ARM_GIC_V3=y\nCONFIG_PROC_CHILDREN=y\n")
            initrd=payload/"initramfs.cpio";initrd.write_bytes(original)
            metadata={"schema":"ostadix.real-linux-payload/v1","profile":"package-domain",
                      "linux_version":"6.12.43","source_modifications":False,
                      "source_archive_sha256":"0fcbbbbcd456e87bbbfc8bf37af541fda62ccfcce76903503424fd101ef7bdee",
                      "artifacts":{name:BUILDER.identity(payload/name)
                                   for name in ("Image","linux.config","initramfs.cpio")}}
            expected,recipe=BUILDER.admit_linux_initramfs(initrd,metadata,template)
            self.assertEqual(recipe["original_sha256"],hashlib.sha256(original).hexdigest())
            self.assertEqual(expected,BUILDER.derive_linux_initramfs(original,template)[0])
            (payload/"linux-payload.json").write_text(json.dumps(metadata))
            initrd.write_bytes(tampered)
            with self.assertRaisesRegex(ValueError,"initramfs differs"):
                BUILDER.build(payload,base/"unused-plan9",base/"unused-admission",
                              base/"output",base/"unused-compiler","unused-clang","unused-lld","unused-dtc")
            self.assertFalse((base/"output").exists())

    def test_initramfs_admission_requires_size_hash_and_regular_original(self):
        template=(ROOT/"ocore/guest/linux/package-domain/init").read_bytes()
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"initramfs.cpio";path.write_bytes(fixture_initramfs())
            item=BUILDER.identity(path)
            for expected in ({},dict(item,bytes=item["bytes"]+1),dict(item,sha256="0"*64)):
                with self.subTest(expected=expected),self.assertRaises(ValueError):
                    BUILDER.admit_linux_initramfs(path,{"artifacts":{"initramfs.cpio":expected}},template)
            with self.assertRaisesRegex(ValueError,"admitted regular"):
                BUILDER.admit_linux_initramfs(path,{"artifacts":{}},template)
            link=path.with_suffix(".link");link.symlink_to(path)
            with self.assertRaisesRegex(ValueError,"admitted regular"):
                BUILDER.admit_linux_initramfs(link,{"artifacts":{"initramfs.cpio":item}},template)

if __name__=="__main__":
    unittest.main()
