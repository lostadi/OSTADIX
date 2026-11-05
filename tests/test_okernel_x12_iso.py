"""Portable artifact and copy-boundary checks; actual boot is a separate gate."""
import hashlib
import importlib.util
import json
from pathlib import Path
import stat
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


builder = load(ROOT / "scripts/build_okernel_x12_iso.py", "x12_iso_builder_tests")
seed = load(ROOT / "ocore/guest/x12-live/seed.py", "x12_iso_seed_tests")
iso_structure = load(ROOT / "scripts/ostadix_boot_iso.py", "x12_iso_fat_tests")


class X12ArtifactBoundaries(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="x12-iso-unit-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def test_checked_copy_rejects_traversal_and_directory_symlink(self):
        original = self.root / "data"
        original.write_bytes(b"\x00\xffpayload")
        pin = {"bytes": original.stat().st_size, "sha256": hashlib.sha256(original.read_bytes()).hexdigest()}
        self.assertEqual(seed.checked(self.root, "data", pin), original)
        (self.root / "link").symlink_to(self.root, target_is_directory=True)
        for relative in ("../data", "/data", "link/data", "./data"):
            with self.subTest(relative=relative), self.assertRaises(ValueError):
                seed.checked(self.root, relative, pin)

    def test_checked_copy_rejects_modified_bytes_or_size(self):
        original = self.root / "data"
        original.write_bytes(b"correct")
        pin = {"bytes": 7, "sha256": hashlib.sha256(b"correct").hexdigest()}
        for payload in (b"CORRECT", b"correct\x00"):
            original.write_bytes(payload)
            with self.assertRaises(ValueError): seed.checked(self.root, "data", pin)

    def test_output_refuses_existing_file_directory_and_symlink(self):
        original = self.root / "file"; original.write_bytes(b"preserve")
        directory = self.root / "directory"; directory.mkdir()
        link = self.root / "link"; link.symlink_to(original)
        for path in (original, directory, link):
            with self.subTest(path=path), self.assertRaises(ValueError): builder.new_output(path)
        self.assertEqual(original.read_bytes(), b"preserve")

    def test_seed_rejects_source_alias_and_output_parent_alias(self):
        original = self.root / "seed"; original.mkdir()
        alias = self.root / "seed-alias"; alias.symlink_to(original, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "symlink"):
            seed.materialize(alias, self.root / "output")
        with self.assertRaisesRegex(ValueError, "symlink"):
            seed.destination(original, alias / "inside")
        with self.assertRaisesRegex(ValueError, "symlink"):
            builder.new_output(alias / "builder-inside")
        self.assertEqual(list(original.iterdir()), [])

    def runtime(self, inventory):
        source = self.root / "runtime"; source.mkdir()
        (source / "entry").write_bytes(b"\x00\xffbytes")
        (source / "runtime.json").write_text(json.dumps({"schema": "ostadix.okernel-unified-runtime/v1",
                                                        "passed": True, "inventory": inventory}))
        return source

    def test_runtime_copy_retains_bound_bytes(self):
        pin = {"bytes": 7, "sha256": hashlib.sha256(b"\x00\xffbytes").hexdigest()}
        source = self.runtime({"entry": pin})
        builder.copy_runtime(source, self.root / "copied")
        self.assertEqual((self.root / "copied/entry").read_bytes(), b"\x00\xffbytes")
        self.assertNotEqual((source / "entry").stat().st_ino, (self.root / "copied/entry").stat().st_ino)

    def test_runtime_inventory_escape_and_symlink_are_rejected(self):
        pin = {"bytes": 7, "sha256": hashlib.sha256(b"\x00\xffbytes").hexdigest()}
        source = self.runtime({"../entry": pin})
        with self.assertRaises(ValueError): builder.copy_runtime(source, self.root / "escaped")
        (source / "alias").symlink_to("entry")
        (source / "runtime.json").write_text(json.dumps({"schema": "ostadix.okernel-unified-runtime/v1",
                                                        "passed": True, "inventory": {"alias": pin}}))
        with self.assertRaises(ValueError): builder.copy_runtime(source, self.root / "symlinked")

    def test_newc_preserves_binary_and_root_device_metadata_without_mknod(self):
        root = self.root / "root"; root.mkdir()
        (root / "dev").mkdir()
        (root / "hello").write_bytes(b"\x00\xffhello\n")
        (root / "alias").symlink_to("hello")
        archive = self.root / "initramfs.cpio"
        builder.newc(root, archive)
        raw = archive.read_bytes(); position = 0; entries = {}
        # Independent fixed-format decoding checks archive metadata/byte lengths.
        while True:
            self.assertEqual(raw[position:position+6], b"070701")
            fields = [int(raw[position+6+i*8:position+14+i*8], 16) for i in range(13)]
            name_start = position + 110
            name = raw[name_start:name_start+fields[11]-1].decode()
            data_start = (name_start + fields[11] + 3) & ~3
            payload = raw[data_start:data_start+fields[6]]
            entries[name] = (fields, payload)
            position = (data_start + fields[6] + 3) & ~3
            if name == "TRAILER!!!": break
        self.assertEqual(entries['hello'][1], b"\x00\xffhello\n")
        self.assertEqual(entries['alias'][1], b"hello")
        self.assertEqual(stat.S_IFMT(entries['alias'][0][1]), stat.S_IFLNK)
        console = entries['dev/console'][0]
        self.assertEqual((stat.S_IFMT(console[1]), console[2], console[3], console[9], console[10]),
                         (stat.S_IFCHR, 0, 0, 5, 1))
        null = entries['dev/null'][0]
        self.assertEqual((null[9], null[10]), (1, 3))
        self.assertFalse((root / "dev/console").exists())

    def fat12(self):
        raw = bytearray(2880 * 512)
        raw[11:13] = (512).to_bytes(2, 'little'); raw[13] = 1
        raw[14:16] = (1).to_bytes(2, 'little'); raw[16] = 2
        raw[17:19] = (224).to_bytes(2, 'little'); raw[19:21] = (2880).to_bytes(2, 'little')
        raw[22:24] = (9).to_bytes(2, 'little'); raw[510:512] = b'\x55\xaa'
        table = bytearray(9*512); table[:3] = b'\xf0\xff\xff'
        for cluster in (2, 3, 4):
            offset = cluster + cluster // 2
            value = int.from_bytes(table[offset:offset+2], 'little')
            value |= 0xfff0 if cluster & 1 else 0x0fff
            table[offset:offset+2] = value.to_bytes(2, 'little')
        raw[512:512+len(table)] = table; raw[512+len(table):512+2*len(table)] = table
        def entry(offset, name, cluster, directory=False, size=0):
            raw[offset:offset+11] = name
            raw[offset+11] = 0x10 if directory else 0x20
            raw[offset+26:offset+28] = cluster.to_bytes(2, 'little')
            raw[offset+28:offset+32] = size.to_bytes(4, 'little')
        entry(19*512, b'EFI        ', 2, True)
        entry(33*512, b'BOOT       ', 3, True)
        entry(34*512, b'BOOTX64 EFI', 4, size=8)
        raw[35*512:35*512+8] = b'EFIbytes'
        raw[36*512:37*512] = b'X' * 512
        return bytes(raw)

    def test_fat_free_normalization_preserves_allocated_boot_and_is_idempotent(self):
        raw = self.fat12()
        canonical, evidence = builder.canonical_fat_free(raw, iso_structure)
        self.assertEqual(evidence['zeroed_nonempty_clusters'], [5])
        self.assertEqual(canonical[:36*512], raw[:36*512])
        self.assertEqual(canonical[37*512:], raw[37*512:])
        self.assertEqual(canonical[36*512:37*512], bytes(512))
        self.assertEqual(builder.canonical_fat_free(canonical, iso_structure)[0], canonical)

    def test_fat_disagreement_and_truncation_fail_before_normalization(self):
        raw = bytearray(self.fat12()); raw[512+9*512+100] = 1
        with self.assertRaisesRegex(ValueError, 'copies disagree'):
            builder.canonical_fat_free(bytes(raw), iso_structure)
        with self.assertRaises(ValueError):
            builder.canonical_fat_free(self.fat12()[:-512], iso_structure)

    def test_retained_notices_copy_exact_bytes_and_reject_changed_source(self):
        source = self.root / 'assembly'; stage = source / 'iso-tree'
        notices = stage / 'licenses'; notices.mkdir(parents=True)
        (notices / 'copyright').write_bytes(b'original upstream notice\n')
        (notices / 'manifest.json').write_bytes(b'{}\n')
        tools = stage / 'carrier-tools'; tools.mkdir()
        dash = tools / 'dash'; dash.write_bytes(b'bound optional binary'); dash.chmod(0o555)
        manifest = {'schema': builder.ISO_SCHEMA, 'ok': True, 'attributions': {
            'inventory': builder.inventory(notices), 'optional_dash': builder.identity(dash)}}
        (source / 'result.json').write_text(json.dumps(manifest))
        target = self.root / 'target'; target.mkdir()
        receipt = builder.retained_attributions(source, target)
        self.assertEqual(builder.inventory(target / 'licenses'), manifest['attributions']['inventory'])
        self.assertEqual((target / 'carrier-tools/dash').read_bytes(), b'bound optional binary')
        self.assertEqual(receipt['optional_dash']['sha256'], manifest['attributions']['optional_dash']['sha256'])
        (notices / 'copyright').write_bytes(b'changed upstream notice\n')
        target2 = self.root / 'target2'; target2.mkdir()
        with self.assertRaisesRegex(ValueError, 'inventory changed'):
            builder.retained_attributions(source, target2)
        self.assertEqual(list(target2.iterdir()), [])


if __name__ == "__main__": unittest.main()
