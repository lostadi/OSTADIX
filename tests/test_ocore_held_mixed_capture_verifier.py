"""UNRUN boundary and genuine partition-body controls; no whole-capture qualification.

The reconstruction boundary controls mock the heavy source/tool builder explicitly.
The partition controls execute the actual production check_requirements/partition_units
bodies with held source/evidence/log fixtures, independently of that mock.
"""
import ast,copy,hashlib,importlib.util,json
from pathlib import Path
import sys,tempfile,unittest
from unittest import mock

class HeldMixedCaptureVerifierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path=Path(__file__).resolve().parents[1]/"scripts"/"ocore_runtime_capture.py"
        spec=importlib.util.spec_from_file_location("held_mixed_worker_control",path)
        cls.worker=importlib.util.module_from_spec(spec)
        sys.modules[spec.name]=cls.worker
        spec.loader.exec_module(cls.worker)

    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name).resolve(); self.journal=self.root/"journal"
        (self.journal/"events").mkdir(parents=True)
        self.source=self.root/"upstream"; self.source.mkdir()
        self.build=self.root/"build"; self.build.mkdir()
        registry_path=Path(self.worker.__file__).with_name("ocore_producer_registry.json")
        registry=self.worker.producer_registry(registry_path)
        self.kind=next(kind for name,kind in self.worker.wrapper_kinds(registry) if name=="clang")
        self.target="riscv64-unknown-linux-gnu"
        c=self.pin(self.source/"original.c",b"int original;\n")
        assembly=self.pin(self.source/"original.s",b".text\noriginal:\n ret\n")
        self.llvm=self.pin(self.root/"unit.ll",
            b'target triple = "riscv64-unknown-linux-gnu"\ndefine i64 @original() { ret i64 0 }\n')
        self.units=[
            {"id":"llvm-unit","kind":self.kind,"producer":"clang-llvm-v1","source":c,
             "ir":{**self.llvm,"format":"llvm-text","target_triple":self.target}},
            {"id":"assembly-unit","kind":self.kind,"producer":"clang-llvm-v1","source":assembly,
             "representation":"configured-assembly","configured_assembly":{
                 "capture_complete":False,"target_triple":self.target}}]
        self.events=[
            {"id":"llvm-action","kind":self.kind,"sources":[copy.deepcopy(c)],
             "state":"finished","exit_code":0,"started_ns":100,"finished_ns":110,
             "execution":{"dispatch_state":"known_reaped"},"capture_errors":[],
             "units":[copy.deepcopy(self.units[0])]},
            {"id":"assembly-action","kind":self.kind,"sources":[copy.deepcopy(assembly)],
             "state":"finished","exit_code":None,"started_ns":200,"finished_ns":210,
             "execution":{"dispatch_state":"constructor_entered_no_handle_unknown"},
             "capture_errors":["terminal authority unavailable"],
             "units":[copy.deepcopy(self.units[1])]}]
        recipe={"schema":"boundary-fixture-heavy-builder-is-mocked"}
        recipepin=self.pin_json(self.root/"recipe.json",recipe)
        workerpin=self.pin(self.journal/"capture-worker.py",b"# held worker fixture\n")
        registrypin=self.pin(self.journal/"registry.json",registry_path.read_bytes())
        inventorypin=self.pin_json(self.root/"inventory.json",{
            "schema":self.worker.INVENTORY_SCHEMA,"complete":True,
            "units":[{"kind":self.kind,"source":"original.c","target_triple":self.target}]})
        self.session={"manifest":recipepin,"recipe":copy.deepcopy(recipe),
            "capture_worker":{"artifact":workerpin,"producer_registry":{"artifact":registrypin}},
            "inventory_artifact":inventorypin,"inventory_path":inventorypin["path"],
            "source":{"path":str(self.source)},"build":str(self.build)}
        sessionpin=self.pin_json(self.journal/"session.json",self.session)
        self.report={"schema":self.worker.MIXED_REPORT_SCHEMA,
            "invocations":copy.deepcopy(self.events),"units":copy.deepcopy(self.units),
            "lowering_unit_ids":["assembly-unit","llvm-unit"],"non_lowering_units":[],
            "unclassified_unit_ids":[],"issues":["UNKNOWN assembly remains required"],
            "failed_required_units":[{"source":"original.s","complete":False}],
            "uncaptured_outputs":[{"path":str(self.root/"unknown.o"),"reason":"unobserved"}],
            "capture_complete":False,"unit_inventory_complete":True,"unit_roles_complete":True}
        native=self.journal.stat()
        self.context={"schema":self.worker.HELD_MIXED_CONTEXT_SCHEMA,
            "journal":{"path":str(self.journal),"device":native.st_dev,"inode":native.st_ino,
                       "events":[]},
            "report":{},"session":sessionpin,"recipe":recipepin,"capture_worker":workerpin,
            "producer_registry":registrypin,"inventory":inventorypin,
            "member_policy":self.pin(self.root/"members.raw",b"required original cohort\n"),
            "original_order_policy":self.pin(self.root/"order.raw",b"B,A,B\n")}
        self.context_path=self.root/"context.json"
        self.refresh()
        self.report_before=(self.journal/"report.json").read_bytes()
        self.context_before=self.context_path.read_bytes()

    def pin(self,path,raw):
        path.write_bytes(raw)
        return {"path":str(path),"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()}
    def pin_json(self,path,value):
        return self.pin(path,(json.dumps(value,sort_keys=True)+"\n").encode())
    def refresh(self):
        self.report["units"]=copy.deepcopy(self.units)
        self.report["invocations"]=copy.deepcopy(self.events)
        self.context["journal"]["events"]=[
            self.pin_json(self.journal/"events"/f"{index:06}.json",event)
            for index,event in enumerate(self.events,1)]
        self.context["report"]=self.pin_json(self.journal/"report.json",self.report)
        self.contextpin=self.pin_json(self.context_path,self.context)
    def builder(self,directory,persist=True,expected_worker_sha256=None,unit_observer=None):
        self.assertEqual(directory,self.journal); self.assertIs(persist,False)
        self.assertEqual(expected_worker_sha256,self.context["capture_worker"]["sha256"])
        for index,unit in enumerate(self.units):
            owners=[event for event in self.events if any(row["id"]==unit["id"] for row in event["units"])]
            checked=index==0
            unit_observer(copy.deepcopy(unit),copy.deepcopy(owners),checked,
                          None if checked else "terminal authority unavailable")
        return copy.deepcopy(self.report)
    def checked_builder(self,directory,persist=True,expected_worker_sha256=None,unit_observer=None):
        self.assertEqual(directory,self.journal); self.assertIs(persist,False)
        for unit in self.units:
            owners=[event for event in self.events if any(row["id"]==unit["id"] for row in event["units"])]
            unit_observer(copy.deepcopy(unit),copy.deepcopy(owners),True,None)
        return copy.deepcopy(self.report)
    def verify(self,builder=None):
        with mock.patch.object(self.worker,"make_report",side_effect=builder or self.builder):
            return self.worker.verify_held_mixed_report(self.journal/"report.json",self.context_path,
                expected_context_bytes=self.contextpin["bytes"],
                expected_context_sha256=self.contextpin["sha256"],
                expected_worker_sha256=self.context["capture_worker"]["sha256"])

    def test_incomplete_cohort_keeps_tags_diagnostics_and_unknown_terminal(self):
        result=self.verify()
        self.assertTrue(result["reconstruction_complete"]); self.assertTrue(result["input_custody_checked"])
        self.assertFalse(result["scoped_capture_complete"])
        self.assertEqual([u["disposition"] for u in result["units"]],["checked","refused"])
        self.assertEqual(result["units"][0]["input"],self.llvm)
        self.assertIsNone(result["units"][1]["input"])
        self.assertIsNone(result["invocation_statuses"][1]["exit_code"])
        self.assertEqual(result["diagnostics"]["failed_required_units"],self.report["failed_required_units"])
        self.assertEqual(result["diagnostics"]["uncaptured_outputs"],self.report["uncaptured_outputs"])
        self.assertEqual(result["shared_inputs"]["original_order_policy"],self.context["original_order_policy"])
        self.assertEqual(Path(self.context["original_order_policy"]["path"]).read_bytes(),b"B,A,B\n")
        self.assertEqual((self.journal/"report.json").read_bytes(),self.report_before)
        self.assertEqual(self.context_path.read_bytes(),self.context_before)
        self.assertTrue(all(v is False for v in result["qualifications"].values()))

    def test_complete_mixed_boundary_uses_genuine_completion_names(self):
        self.units[1]["configured_assembly"]={"capture_complete":True,"target_triple":self.target,
            "configured":copy.deepcopy(self.units[1]["source"])}
        self.events[1].update(exit_code=0,execution={"dispatch_state":"known_reaped"},capture_errors=[])
        self.events[1]["units"]=[copy.deepcopy(self.units[1])]
        self.report.update(capture_complete=True,unit_inventory_complete=True,unit_roles_complete=True,
                           issues=[],failed_required_units=[],uncaptured_outputs=[])
        self.refresh()
        self.assertNotIn("inventory_complete",self.report)
        self.assertNotIn("inventory_roles_complete",self.report)
        result=self.verify(self.checked_builder)
        self.assertTrue(result["scoped_capture_complete"])
        self.assertTrue(result["inventory_complete"]); self.assertTrue(result["inventory_roles_complete"])
        self.assertEqual([u["representation"] for u in result["units"]],["llvm","configured-assembly"])

    def partition_case(self):
        probe_source=self.pin(self.source/"probe.c",b"int probe;\n")
        probe_ir=self.pin(self.root/"probe.ll",
            b'target triple = "riscv64-unknown-linux-gnu"\ndefine i64 @probe() { ret i64 0 }\n')
        probe={"id":"host-probe","kind":self.kind,"producer":"clang-llvm-v1","source":probe_source,
               "ir":{**probe_ir,"format":"llvm-text","target_triple":self.target}}
        runtime=copy.deepcopy(self.events[0])
        probe_event={"id":"probe-action","kind":self.kind,"sources":[copy.deepcopy(probe_source)],
            "state":"finished","exit_code":0,"started_ns":12,"finished_ns":15,
            "build_step":{"index":0,"name":"configure"},
            "execution":{"dispatch_state":"known_reaped"},"capture_errors":[],
            "units":[copy.deepcopy(probe)]}
        events=[runtime,probe_event]
        requirements=self.worker.check_requirements(
            [{"kind":self.kind,"source":"original.c","target_triple":self.target}],events,self.source)
        self.assertEqual(requirements[0]["captured_unit_ids"],["llvm-unit"])
        self.assertTrue(requirements[0]["complete"])
        artifact=self.pin(self.root/"probe-result",b"original held configure result\n")
        log=self.pin(self.root/"configure.log",b"original held configure log\n")
        inventory={"schema":self.worker.INVENTORY_SCHEMA,"complete":True,
            "units":[{"kind":self.kind,"source":"original.c","target_triple":self.target}],
            "non_lowering_units":[{"id":"probe-rule","role":"configure_probe","unit_ids":["host-probe"],
                "evidence":{"reason":"original configure-only result","artifacts":[artifact]}}]}
        inventorypin=self.pin_json(self.root/"partition-inventory.json",inventory)
        return {"units":[copy.deepcopy(self.units[0]),probe],"events":events,"required":requirements,
            "inventory":inventory,"inventory_info":inventorypin,
            "steps":[{"name":"configure","argv":["original-held-probe"],"cwd":str(self.build),
                      "exit_code":0,"started_ns":10,"finished_ns":20,"log":log["path"]}],
            "membership":{"complete":True,"contributing_invocation_ids":["llvm-action"]}}

    def partition(self,case,membership=None):
        return self.worker.partition_units(case["units"],case["required"],case["inventory"],
            case["inventory_info"],case["events"],case["steps"],self.source,
            membership=case["membership"] if membership is None else membership)

    def install_partition(self,case,partition):
        self.units=copy.deepcopy(case["units"]); self.events=copy.deepcopy(case["events"])
        self.context["inventory"]=copy.deepcopy(case["inventory_info"])
        self.session["inventory_artifact"]=copy.deepcopy(case["inventory_info"])
        self.session["inventory_path"]=case["inventory_info"]["path"]
        self.context["session"]=self.pin_json(self.journal/"session.json",self.session)
        self.report.update(lowering_unit_ids=copy.deepcopy(partition["lowering_unit_ids"]),
            non_lowering_units=copy.deepcopy(partition["non_lowering_units"]),
            unclassified_unit_ids=copy.deepcopy(partition["unclassified_unit_ids"]),
            capture_complete=partition["complete"],unit_inventory_complete=True,
            unit_roles_complete=partition["complete"],issues=copy.deepcopy(partition["issues"]),
            failed_required_units=[],uncaptured_outputs=[])
        self.refresh()

    def test_genuine_partition_positive_projects_unit_id_and_hashed_evidence(self):
        case=self.partition_case(); before=copy.deepcopy(case)
        partition=self.partition(case)
        self.assertEqual(case,before)
        self.assertTrue(partition["complete"])
        self.assertEqual(partition["non_lowering_units"][0]["unit_id"],"host-probe")
        self.assertIn("sha256",partition["non_lowering_units"][0]["evidence"]["build_step"]["log"])
        self.install_partition(case,partition)
        result=self.verify(self.checked_builder)
        self.assertTrue(result["scoped_capture_complete"])
        self.assertEqual(result["partition"]["non_lowering_unit_ids"],["host-probe"])

    def test_genuine_partition_contributing_probe_refusal_is_retained(self):
        case=self.partition_case(); before=copy.deepcopy(case)
        membership=copy.deepcopy(case["membership"])
        membership["contributing_invocation_ids"].append("probe-action")
        partition=self.partition(case,membership)
        self.assertEqual(case,before)
        self.assertFalse(partition["complete"])
        self.assertEqual(partition["unclassified_unit_ids"],["host-probe"])
        self.assertTrue(any("contributes to a declared runtime output" in row for row in partition["issues"]))
        self.install_partition(case,partition)
        result=self.verify(self.checked_builder)
        self.assertFalse(result["scoped_capture_complete"])
        self.assertEqual(result["diagnostics"]["issues"],partition["issues"])
        self.assertEqual(result["partition"]["unclassified_unit_ids"],["host-probe"])

    def test_genuine_partition_duplicate_ids_remain_failure(self):
        case=self.partition_case()
        case["units"].append(copy.deepcopy(case["units"][0]))
        partition=self.partition(case)
        self.assertFalse(partition["complete"])
        self.assertIn("duplicate captured LLVM unit IDs",partition["issues"])

    def test_genuine_make_report_declares_the_projected_source_fields(self):
        source=Path(self.worker.__file__).read_text()
        function=next(n for n in ast.parse(source).body if isinstance(n,ast.FunctionDef) and n.name=="make_report")
        assignments=[n for n in ast.walk(function) if isinstance(n,ast.Assign)
            and any(isinstance(t,ast.Name) and t.id=="report" for t in n.targets)
            and isinstance(n.value,ast.Dict)]
        self.assertEqual(len(assignments),1)
        keys={k.value for k in assignments[0].value.keys if isinstance(k,ast.Constant) and isinstance(k.value,str)}
        self.assertTrue({"capture_complete","unit_inventory_complete","unit_roles_complete",
                         "failed_required_units","uncaptured_outputs"}.issubset(keys))
        self.assertFalse({"inventory_complete","inventory_roles_complete",
                          "failed_required","uncaptured_invocations"} & keys)

    def test_duplicate_nested_keys_and_nonfinite_numbers_refused(self):
        for raw in (b'{"outer":{"x":1,"x":2}}',b'{"x":NaN}',b'{"x":Infinity}',
                    b'{"x":1e999}',b'{"x":-1e999}'):
            with self.subTest(raw=raw),self.assertRaises(self.worker.CaptureError):
                self.worker._mixed_json(raw,"control")
    def test_raw_pin_length_refuses_bool_float(self):
        for bad in (True,1.0):
            with self.subTest(bad=bad),self.assertRaises(self.worker.CaptureError):
                self.worker._mixed_pin({**self.llvm,"bytes":bad},"control")
    def test_extra_rebuilt_field_refused(self):
        def changed(*a,**k):
            value=self.builder(*a,**k); value["extra"]=True; return value
        with self.assertRaisesRegex(self.worker.CaptureError,"exact typed"):self.verify(changed)
    def test_bool_integer_equality_cannot_substitute(self):
        snapshot=copy.deepcopy(self.report); self.report["capture_complete"]=0
        self.context["report"]=self.pin_json(self.journal/"report.json",self.report)
        self.contextpin=self.pin_json(self.context_path,self.context)
        def changed(*a,**k):
            self.builder(*a,**k); return copy.deepcopy(snapshot)
        with self.assertRaisesRegex(self.worker.CaptureError,"exact typed"):self.verify(changed)
    def test_inventory_write_is_real_postguard_failure(self):
        report_snapshot=copy.deepcopy(self.report); context_snapshot=copy.deepcopy(self.context)
        def changed(*a,**k):
            value=self.builder(*a,**k)
            p=Path(self.context["inventory"]["path"]); p.write_bytes(p.read_bytes()+b" ")
            return value
        with self.assertRaisesRegex(self.worker.CaptureError,"postguard"):self.verify(changed)
        self.assertEqual(self.report,report_snapshot);self.assertEqual(self.context,context_snapshot)
    def test_extra_event_is_membership_failure(self):
        (self.journal/"events"/"000003.json").write_text("{}")
        with self.assertRaisesRegex(self.worker.CaptureError,"membership"):self.verify()
    def test_event_scan_error_is_not_empty_journal(self):
        with mock.patch.object(self.worker.os,"scandir",side_effect=PermissionError("held scan denied")):
            with mock.patch.object(self.worker,"make_report") as builder:
                with self.assertRaisesRegex((PermissionError,self.worker.CaptureError),"held scan denied"):
                    self.worker.verify_held_mixed_report(self.journal/"report.json",self.context_path,
                        expected_context_bytes=self.contextpin["bytes"],
                        expected_context_sha256=self.contextpin["sha256"],
                        expected_worker_sha256=self.context["capture_worker"]["sha256"])
                builder.assert_not_called()
    def test_existing_receipt_not_replaced(self):
        p=self.root/"receipt.json";p.write_bytes(b"prior")
        with self.assertRaises(FileExistsError):self.worker._mixed_publish_receipt(p,b"new",set(),set())
        self.assertEqual(p.read_bytes(),b"prior")
    def test_receipt_inside_journal_refused_without_write(self):
        p=self.journal/"new-receipt.json"
        with self.assertRaisesRegex(self.worker.CaptureError,"capture inputs"):
            self.worker._mixed_publish_receipt(p,b"new",set(),{str(self.journal)})
        self.assertFalse(p.exists())
    def test_wrong_external_context_pin_precedes_builder(self):
        with mock.patch.object(self.worker,"make_report") as builder:
            with self.assertRaisesRegex(self.worker.CaptureError,"external selection"):
                self.worker.verify_held_mixed_report(self.journal/"report.json",self.context_path,
                    expected_context_bytes=self.contextpin["bytes"],expected_context_sha256="0"*64,
                    expected_worker_sha256=self.context["capture_worker"]["sha256"])
            builder.assert_not_called()

if __name__=="__main__":
    unittest.main()
