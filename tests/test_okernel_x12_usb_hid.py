"""Isolated USB-proof boundaries; these tests never start QEMU."""
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock
import zlib


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("x12_usb_hid", ROOT / "scripts/verify_okernel_x12_usb_hid.py")
hid = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(hid)


class FakeQMP:
    def __init__(self):
        self.calls = []
        self.running = True
        self.send_key_runstates = []

    def execute(self, name, arguments=None):
        self.calls.append((name, arguments))
        if name == 'stop': self.running = False
        if name == 'cont': self.running = True
        if name == 'query-status':
            return {'running': self.running, 'status': 'running' if self.running else 'paused'}
        if name == 'send-key': self.send_key_runstates.append(self.running)


class USBProofBoundaries(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="x12-usb-proof-unit-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.record = {"ok": False, "events": []}
        self.qmp = FakeQMP()
        self.frames = []
        self.pixels = b"\x00\xff\x01" * 16 * 16
        def screen(label):
            path = self.root / (str(len(self.frames)) + "-" + label + ".png")
            ppm = path.with_suffix('.ppm'); ppm.write_bytes(b"P6\n16 16\n255\n" + self.pixels)
            path.write_bytes(hid.ppm_to_png(ppm.read_bytes()))
            item = {"stage": self.proof.stage, "png": hid.identity(path),
                    "ppm": hid.identity(ppm), "paused": self.proof.paused}
            self.frames.append(item)
            self.proof.screens[path.name] = item
            self.proof.observe_screen(item)
            return item
        self.proof = hid.USBProof(self.qmp, self.record, "hidabcdef0123",
                                 lambda event: self.record["events"].append(event), screen,
                                 sleep=lambda seconds: None)

    def command(self, action, observed):
        return {"action": action, "screenshot": Path(self.frames[-1]["png"]["path"]).name,
                "observed_text": observed}

    def test_profile_has_only_usb_keyboard_and_readonly_iso_without_shares(self):
        argv = hid.profile(Path("/exact.iso"), Path("/qemu"), Path("/ovmf"), 4096, Path("/private/q"))
        self.assertEqual(argv[argv.index("-machine") + 1], "q35,i8042=off")
        devices = [argv[i + 1] for i, arg in enumerate(argv) if arg == "-device"]
        self.assertEqual(devices, ["ide-cd,drive=live,bus=ide.0", "VGA",
                                   "qemu-xhci,id=xhci", "usb-kbd,id=usbkbd,bus=xhci.0"])
        self.assertIn("-nodefaults", argv)
        self.assertFalse(any(x in argv for x in ["-virtfs", "-fsdev", "-hda", "-hdb", "-vnc"]))
        self.assertNotIn("okernel.console=serial", hid.KERNEL_ARGUMENTS)
        self.assertIn("console=ttyS0,115200n8 console=tty0", hid.KERNEL_ARGUMENTS)
        self.assertNotIn("quiet", hid.KERNEL_ARGUMENTS)
        self.assertIn("module_blacklist=usbkbd", hid.KERNEL_ARGUMENTS)

    def test_usb_driver_evidence_requires_hid_child_and_rejects_boot_fallback(self):
        base = (hid.HELPER + b"\ninput: QEMU QEMU USB Keyboard as /devices/usb1/input1\n"
                b"usbhid: USB HID core driver\n")
        self.assertIsNone(hid.usb_driver_evidence(base))
        generic = b"hid-generic 0003:0627:0001.0001: input,hidraw0: USB HID v1.11 Keyboard [QEMU QEMU USB Keyboard] on usb1\n"
        self.assertIsNotNone(hid.usb_driver_evidence(base + generic))
        with self.assertRaisesRegex(ValueError, "fallback"):
            hid.usb_driver_evidence(base + generic + b"usbcore: registered new interface driver usbkbd\n")
        vt = hid.usb_driver_evidence(base.replace(hid.HELPER+b'\n',b'') + generic, require_uart_helper=False)
        self.assertIsNotNone(vt)
        self.assertNotIn('helper_readback_uart_marker', vt)

    def test_serial_is_unusable_for_guest_input_after_boot(self):
        sent = []; record = {}; serial = hid.SerialBoot(sent.append, record)
        serial.send(b"c")
        for command in hid.BOOT_COMMANDS:
            serial.send(command.encode() + b"\r")
        with self.assertRaisesRegex(ValueError, "prohibited"):
            serial.send(b"n\n")
        self.assertEqual(len(sent), 4)
        self.assertTrue(serial.boot_sent)

    def test_grub_requires_settled_ending_prompt_not_old_echo(self):
        self.assertFalse(hid.settled_grub_prompt(b"grub>grub> ", .1))
        self.assertFalse(hid.settled_grub_prompt(b"grub> linux /boot/vmlinuz\r\n", 2))
        self.assertFalse(hid.settled_grub_prompt(b"grub> linux /boot/vmlinuz\r\nerror: bad\r\n", 2))
        self.assertTrue(hid.settled_grub_prompt(b"grub>grub> \x1b[09;07H", .3))
        serial = hid.SerialBoot(lambda data: None, {})
        serial.send(b"\x15boot\r")
        self.assertTrue(serial.boot_sent)

    def test_network_keys_and_unique_token_are_sent_once_and_only_via_usb(self):
        self.proof.queue_network_entry()
        with self.assertRaisesRegex(ValueError, "no replay"):
            self.proof.queue_network_entry()
        control = self.command("network_prompt_visible", "Interface (for example eth0):")
        self.proof.send_token(control, steps=2, milliseconds=5)
        codes = [args["keys"][0]["data"] for name, args in self.qmp.calls if name == "send-key"]
        self.assertEqual(codes, ["n", "ret", *self.proof.token, "ret"])
        self.assertTrue(all(self.qmp.send_key_runstates))
        self.assertTrue(all(x['observed_qmp_runstate']['running'] for x in self.record['usb_key_inputs']))
        self.assertTrue(self.proof.paused)
        self.assertEqual(self.proof.stage, "await-invalid-interface")
        count = len(self.qmp.calls)
        with self.assertRaises(ValueError): self.proof.send_token(control, steps=2, milliseconds=5)
        self.assertEqual(len(self.qmp.calls), count)

    def test_success_requires_phase_bound_screenshot_token_and_error(self):
        self.proof.queue_network_entry()
        old = self.command("invalid_interface_visible", self.proof.token + " Invalid interface.")
        with self.assertRaises(ValueError): self.proof.confirm_error(old)
        self.proof.send_token(self.command("network_prompt_visible", "Interface (for example eth0):"), 1, 5)
        with self.assertRaisesRegex(ValueError, "required"):
            self.proof.confirm_error(self.command("invalid_interface_visible", "Invalid interface."))
        self.assertFalse(self.record["ok"])
        with self.assertRaises(ValueError): self.proof.confirm_error(old)
        self.proof.confirm_error(self.command("invalid_interface_visible", self.proof.token + " Invalid interface."))
        self.assertTrue(self.record["ok"])
        self.assertEqual(self.record["received_usb_input_proof"]["method"], "manual visual observation")

    def test_changed_screenshot_is_rejected_before_typing_token(self):
        self.proof.queue_network_entry()
        control = self.command("network_prompt_visible", "Interface (for example eth0):")
        Path(self.frames[-1]["png"]["path"]).write_bytes(b"changed")
        calls = len(self.qmp.calls)
        with self.assertRaisesRegex(ValueError, "changed"):
            self.proof.send_token(control, 1, 5)
        self.assertEqual(calls, len(self.qmp.calls))

    def test_advance_and_key_alphabet_are_bounded(self):
        with self.assertRaises(ValueError): self.proof.advance(5)
        with self.assertRaises(ValueError): self.proof.key("ctrl-c")
        self.proof.stage = "await-invalid-interface"
        for invalid in [0, 101]:
            with self.assertRaises(ValueError): self.proof.advance(invalid)
        self.assertEqual(self.qmp.calls, [])

    def test_manual_entry_watch_ignores_cursor_and_pauses_new_content_without_text_claim(self):
        self.proof.begin_manual_entry()
        reference = self.command("arm_entry_watch", "")
        self.proof.arm_entry_watch(reference)
        original = self.pixels
        self.pixels = original[:-16*2*3] + bytes(16*2*3)
        self.proof.screenshot("cursor-only")
        self.assertFalse(self.proof.paused)
        self.pixels = bytes(16*9*3) + original[16*9*3:]
        self.proof.screenshot("new-content")
        self.assertTrue(self.proof.paused)
        self.assertFalse(self.proof.network_keys_sent)
        self.assertNotIn("entry_prompt_evidence", self.record)
        self.assertTrue(self.frames[-1]["paused"])
        self.assertFalse(any(name == "send-key" for name, args in self.qmp.calls))

    def test_manual_entry_requires_real_paused_phase_frame_before_once_only_keys(self):
        self.proof.begin_manual_entry()
        control = self.command("entry_prompt_visible", "Type n within eight seconds to configure host networking")
        with self.assertRaisesRegex(ValueError, "paused"):
            self.proof.confirm_entry(control)
        self.proof.pause(); self.proof.screenshot("paused-prompt")
        self.proof.confirm_entry(self.command("entry_prompt_visible", "Type n within eight seconds to configure host networking"))
        self.assertFalse(self.proof.paused)
        self.assertEqual(self.proof.stage, "await-network-prompt")
        self.assertEqual([args['keys'][0]['data'] for name,args in self.qmp.calls if name=='send-key'], ['n','ret'])
        cont = next(i for i,(name,args) in enumerate(self.qmp.calls) if name=='cont')
        first_key = next(i for i,(name,args) in enumerate(self.qmp.calls) if name=='send-key')
        self.assertLess(cont, first_key)
        self.assertEqual(self.qmp.send_key_runstates, [True, True])
        with self.assertRaises(ValueError): self.proof.confirm_entry(control)

    def test_paused_or_unexpected_actual_runstate_cannot_silently_drop_input(self):
        self.proof.pause()
        calls = len(self.qmp.calls)
        with self.assertRaisesRegex(ValueError, 'paused'): self.proof.key('n')
        self.assertEqual(len(self.qmp.calls), calls)
        self.proof.paused = False  # Simulate a stale local state flag.
        with self.assertRaisesRegex(ValueError, 'observed QMP'): self.proof.key('n')
        self.assertEqual(self.qmp.send_key_runstates, [])

    def test_each_stroke_drains_before_any_next_key_or_pause(self):
        sleeps = []; self.proof.sleep = sleeps.append
        self.proof.queue_network_entry()
        self.proof.send_token(self.command('network_prompt_visible','Interface (for example eth0):'), 1, 5)
        self.assertTrue(all(self.qmp.send_key_runstates))
        self.assertEqual(sleeps.count(.08), 2 + len(self.proof.token) + 1)
        for i,(name,args) in enumerate(self.qmp.calls):
            if name == 'send-key': self.assertEqual(self.qmp.calls[i-1][0], 'query-status')

    def test_causal_helper_binding_requires_actual_reviewed_entry_before_keys(self):
        self.record['helper_readback_evidence'] = {'requires_actual_entry_prompt': True}
        with self.assertRaisesRegex(ValueError, 'actual reviewed entry'): self.proof.key('n')
        self.proof.begin_manual_entry(); self.proof.pause(); self.proof.screenshot('paused-entry')
        self.proof.confirm_entry(self.command('entry_prompt_visible','Type n within eight seconds'))
        self.assertIn('actual_entry_prompt', self.record['helper_readback_evidence'])
        self.assertTrue(all(self.qmp.send_key_runstates))

    def synthetic_iso(self, payload):
        raw = bytearray(24*2048)
        def both32(buf, off, value):
            buf[off:off+4] = value.to_bytes(4,'little')
            buf[off+4:off+8] = value.to_bytes(4,'big')
        def entry(name, lba, size, directory=False):
            buf = bytearray(33+len(name)+(not len(name)%2))
            buf[0] = len(buf); both32(buf,2,lba); both32(buf,10,size)
            buf[25] = 2 if directory else 0; buf[32] = len(name); buf[33:33+len(name)] = name
            return buf
        pvd = bytearray(2048); pvd[:7] = b'\x01CD001\x01'; both32(pvd,80,24)
        root = entry(b'\0',20,2048,True); pvd[156:156+len(root)] = root
        raw[16*2048:17*2048] = pvd
        boot = entry(b'BOOT',21,2048,True); raw[20*2048:20*2048+len(boot)] = boot
        file = entry(b'ROOTFS.SQU;1',22,len(payload))
        nm = b'NM' + bytes([5+len(b'rootfs.squashfs'),1,0]) + b'rootfs.squashfs'
        file.extend(nm); file[0] = len(file)
        raw[21*2048:21*2048+len(file)] = file
        raw[22*2048:22*2048+len(payload)] = payload
        path = self.root/'synthetic.iso'; path.write_bytes(raw)
        return path

    def test_direct_iso_extent_and_contained_guard_binding_reject_changed_payload(self):
        init = (b"#!/bin/sh\nset -eu\n[ -x /usr/bin/mdev ]\n"
                b"printf '%s\\n' /usr/bin/mdev > /proc/sys/kernel/hotplug\n"
                b'[ "$(cat /proc/sys/kernel/hotplug)" = /usr/bin/mdev ]\n'
                b"echo 'OKERNEL X12 HOTPLUG DRIVER HELPER: /usr/bin/mdev' >/dev/console\n"
                b"modprobe -a -b -- $aliases 2>/dev/null || true\n")
        def pin(raw): return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
        metadata = json.dumps({'helpers':{'init':pin(init)}}).encode()
        payload = b'bound-squashfs-bytes'; iso = self.synthetic_iso(payload)
        receipt = {'squashfs':pin(payload),'root_inventory':{'usr/sbin/init':pin(init),
                   'usr/share/okernel/image.json':pin(metadata)}}
        tool = self.root/'unsquashfs'; tool.write_bytes(b'bound-read-tool')
        result = mock.Mock(returncode=0,stdout=init+metadata,stderr=b'')
        with mock.patch.object(hid.shutil,'which',return_value=str(tool)), mock.patch.object(hid.subprocess,'run',return_value=result) as run:
            binding = hid.bind_helper_preflight(iso, receipt, required_init_sha=pin(init)['sha256'])
            self.assertEqual(binding['contained_squashfs']['iso_offset'],22*2048)
            self.assertFalse(binding['uart_helper_literal_claimed'])
            self.assertTrue(binding['requires_actual_entry_prompt'])
            self.assertIn('-cat',run.call_args.args[0])
            raw = bytearray(iso.read_bytes()); raw[22*2048] ^= 1; iso.write_bytes(raw)
            run.reset_mock()
            with self.assertRaisesRegex(ValueError,'SquashFS'): hid.bind_helper_preflight(iso,receipt)
            run.assert_not_called()

    def test_guard_order_and_missing_readback_do_not_qualify_helper(self):
        raw = (ROOT/'ocore/guest/x12-live/init').read_bytes()
        offsets = hid.verify_init_guards(raw)
        self.assertLess(offsets['[ "$(cat /proc/sys/kernel/hotplug)" = /usr/bin/mdev ]'],
                        offsets['modprobe -a -b -- $aliases 2>/dev/null || true'])
        with self.assertRaisesRegex(ValueError,'guards'):
            hid.verify_init_guards(raw.replace(b'[ "$(cat /proc/sys/kernel/hotplug)" = /usr/bin/mdev ]',b': # missing readback'))

    def test_ppm_conversion_retains_exact_rgb_and_checks_lengths(self):
        pixels = b"\x00\xff\x01\x22\x0a\x80"
        png = hid.ppm_to_png(b"P6\n2 1\n255\n" + pixels)
        self.assertTrue(png.startswith(b"\x89PNG\r\n\x1a\n"))
        pos = 8; data = b""
        while pos < len(png):
            n = struct.unpack(">I", png[pos:pos+4])[0]; kind = png[pos+4:pos+8]
            content = png[pos+8:pos+8+n]
            self.assertEqual(zlib.crc32(kind + content), struct.unpack(">I", png[pos+8+n:pos+12+n])[0])
            if kind == b"IDAT": data += content
            pos += n + 12
        self.assertEqual(zlib.decompress(data), b"\0" + pixels)
        for raw in [b"P6\n2 1\n255\n" + pixels[:-1], b"P3\n2 1\n255\n" + pixels]:
            with self.assertRaises(ValueError): hid.ppm_to_png(raw)

    def test_output_refuses_existing_and_symlink_parent(self):
        directory = self.root / "existing"; directory.mkdir()
        alias = self.root / "alias"; alias.symlink_to(directory, target_is_directory=True)
        with self.assertRaises(FileExistsError): hid.new_output(directory)
        with self.assertRaises(ValueError): hid.new_output(alias / "output")

    def test_default_cli_prints_plan_without_starting_process_or_creating_output(self):
        iso = self.root / "media.iso"; iso.write_bytes(b"exact image bytes")
        firmware = self.root / "ovmf"; firmware.write_bytes(b"firmware")
        qemu = self.root / "qemu"; qemu.write_bytes(b"tool identity")
        out = io.StringIO()
        with mock.patch("sys.argv", ["usb-proof", "--iso", str(iso), "--firmware", str(firmware),
                                     "--qemu", str(qemu)]), mock.patch.object(hid.subprocess, "Popen") as popen:
            with contextlib.redirect_stdout(out): self.assertEqual(hid.main(), 0)
        popen.assert_not_called()
        plan = json.loads(out.getvalue())
        self.assertTrue(plan["launch_disabled"])
        self.assertFalse(plan["ok"])
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), ["media.iso", "ovmf", "qemu"])


if __name__ == "__main__":
    unittest.main()
