"""Independent LLVM C-API graph reader; never imports the production importer.

Only MDTuple and MDString are accepted. Source roots are original instruction
operands followed by the actual noalias-relevant attachment enumeration.
Display labels are never read as identities or rewritten.
"""
import ctypes as C
from pathlib import Path

P=C.c_void_p;U=C.c_uint;S=C.c_size_t
class GraphOracle:
    def __init__(self,library):
        self.lib=C.CDLL(str(library))
        signatures={
          'LLVMContextCreate':(P,[]),'LLVMContextDispose':(None,[P]),
          'LLVMCreateMemoryBufferWithMemoryRangeCopy':(P,[C.c_char_p,S,C.c_char_p]),
          'LLVMDisposeMemoryBuffer':(None,[P]),'LLVMDisposeModule':(None,[P]),
          'LLVMParseIRInContext2':(C.c_int,[P,P,C.POINTER(P),C.POINTER(P)]),
          'LLVMVerifyModule':(C.c_int,[P,C.c_int,C.POINTER(P)]),
          'LLVMDisposeMessage':(None,[P]),'LLVMGetVersion':(None,[C.POINTER(U)]*3),
          'LLVMGetFirstFunction':(P,[P]),'LLVMGetNextFunction':(P,[P]),
          'LLVMGetFirstBasicBlock':(P,[P]),'LLVMGetNextBasicBlock':(P,[P]),
          'LLVMGetFirstInstruction':(P,[P]),'LLVMGetNextInstruction':(P,[P]),
          'LLVMGetValueName2':(P,[P,C.POINTER(S)]),'LLVMGetInstructionOpcode':(U,[P]),
          'LLVMGetCalledValue':(P,[P]),'LLVMIsAFunction':(P,[P]),
          'LLVMGetNumArgOperands':(U,[P]),'LLVMGetOperand':(P,[P,U]),
          'LLVMTypeOf':(P,[P]),'LLVMGetTypeKind':(U,[P]),
          'LLVMValueAsMetadata':(P,[P]),'LLVMMetadataAsValue':(P,[P,P]),
          'LLVMGetMetadataKind':(U,[P]),'LLVMGetMDNodeNumOperands':(U,[P]),
          'LLVMGetMDNodeOperands':(None,[P,C.POINTER(P)]),
          'LLVMGetMDString':(P,[P,C.POINTER(U)]),'LLVMPrintValueToString':(P,[P]),
          'LLVMGetMDKindIDInContext':(U,[P,C.c_char_p,U]),
          'LLVMInstructionGetAllMetadataOtherThanDebugLoc':(P,[P,C.POINTER(S)]),
          'LLVMValueMetadataEntriesGetKind':(U,[P,U]),
          'LLVMValueMetadataEntriesGetMetadata':(P,[P,U]),
          'LLVMDisposeValueMetadataEntries':(None,[P]),
        }
        for name,(result,args) in signatures.items():
            f=getattr(self.lib,name);f.restype=result;f.argtypes=args
        version=[U() for _ in range(3)]
        self.lib.LLVMGetVersion(*(C.byref(x) for x in version))
        assert tuple(x.value for x in version)==(22,1,6)
    @staticmethod
    def each(first,next_,parent):
        p=first(parent)
        while p:
            yield p;p=next_(p)
    def read(self,path):
        a=self.lib;raw=Path(path).read_bytes();ctx=a.LLVMContextCreate();buf=None;mod=P();msg=P()
        try:
            buf=a.LLVMCreateMemoryBufferWithMemoryRangeCopy(raw,len(raw),str(path).encode())
            if a.LLVMParseIRInContext2(ctx,buf,C.byref(mod),C.byref(msg)):
                raise AssertionError(C.string_at(msg).decode() if msg else 'LLVM parse failed')
            if msg:a.LLVMDisposeMessage(msg);msg=P()
            if a.LLVMVerifyModule(mod,2,C.byref(msg)):
                raise AssertionError(C.string_at(msg).decode() if msg else 'LLVM verify failed')
            kinds={a.LLVMGetMDKindIDInContext(ctx,k,len(k)):v for k,v in
                   [(b'alias.scope','alias_scope'),(b'noalias','noalias')]}
            roots=[]
            for fn in self.each(a.LLVMGetFirstFunction,a.LLVMGetNextFunction,mod):
                length=S();name=a.LLVMGetValueName2(fn,C.byref(length));name=C.string_at(name,length.value).decode()
                for bi,block in enumerate(self.each(a.LLVMGetFirstBasicBlock,a.LLVMGetNextBasicBlock,fn)):
                    for ii,inst in enumerate(self.each(a.LLVMGetFirstInstruction,a.LLVMGetNextInstruction,block)):
                        site={'function':name,'block':bi,'source_instruction':ii}
                        if a.LLVMGetInstructionOpcode(inst)==45:
                            called=a.LLVMGetCalledValue(inst)
                            if called and a.LLVMIsAFunction(called):
                                n=S();label=a.LLVMGetValueName2(called,C.byref(n));label=C.string_at(label,n.value)
                                if label==b'llvm.experimental.noalias.scope.decl':
                                    assert a.LLVMGetNumArgOperands(inst)==1
                                    argument=a.LLVMGetOperand(inst,0)
                                    assert a.LLVMGetTypeKind(a.LLVMTypeOf(argument))==14
                                    roots.append(('scope_declaration',site,a.LLVMValueAsMetadata(argument)))
                        count=S();entries=a.LLVMInstructionGetAllMetadataOtherThanDebugLoc(inst,C.byref(count))
                        try:
                            for index in range(count.value):
                                kind=a.LLVMValueMetadataEntriesGetKind(entries,index)
                                if kind in kinds:
                                    roots.append((kinds[kind],site,a.LLVMValueMetadataEntriesGetMetadata(entries,index)))
                        finally:
                            if entries:a.LLVMDisposeValueMetadataEntries(entries)
            nodes=[];seen={};raw_tuples=[]
            def visit(md):
                assert md
                if md in seen:return seen[md]
                index=len(nodes);seen[md]=index;nodes.append(None)
                kind=a.LLVMGetMetadataKind(md)
                value=a.LLVMMetadataAsValue(ctx,md)
                assert value and a.LLVMValueAsMetadata(value)==md
                if kind==0:
                    length=U();data=a.LLVMGetMDString(value,C.byref(length))
                    nodes[index]={'kind':'string','id':index,'metadata_kind':0,
                                  'bytes':list(C.string_at(data,length.value)) if length.value else []}
                elif kind==4:
                    printed=a.LLVMPrintValueToString(value)
                    assert printed
                    try:text=C.string_at(printed)
                    finally:a.LLVMDisposeMessage(printed)
                    # Anchored storage classification only, never pointer labels.
                    _,sep,body=text.partition(b' = ');assert sep
                    if body.startswith(b'distinct !{'):storage='distinct'
                    elif body.startswith(b'!{'):storage='uniqued'
                    else:raise AssertionError('unsupported source tuple storage')
                    raw_tuples.append({'node':index,'bytes':list(text)})
                    n=a.LLVMGetMDNodeNumOperands(value);values=(P*n)();a.LLVMGetMDNodeOperands(value,values)
                    operands=[]
                    for child in values:
                        assert child
                        operands.append(visit(a.LLVMValueAsMetadata(child)))
                    nodes[index]={'kind':'tuple','id':index,'metadata_kind':4,
                                  'storage':storage,'operands':operands}
                else:raise AssertionError(f'unsupported metadata subclass {kind}')
                return index
            result_roots=[{'kind':kind,'site':site,'node':visit(md)} for kind,site,md in roots]
            return {'nodes':nodes,'roots':result_roots,'raw_tuples':raw_tuples}
        finally:
            if msg:a.LLVMDisposeMessage(msg)
            if mod:a.LLVMDisposeModule(mod)
            if buf:a.LLVMDisposeMemoryBuffer(buf)
            a.LLVMContextDispose(ctx)
