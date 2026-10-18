//! A bounded-semantics, owned-code leaf beneath the admitted graph executor.
//!
//! The ordinary O call embeds its complete module. The adapter audits every
//! function (including unreachable blocks), emits owned assembly, and constructs
//! a static Linux executable before admission. Sealed ELF handles, rather than
//! caller-supplied executables or descriptive maps, carry launch authority.

use std::collections::{BTreeMap, VecDeque};
#[cfg(target_os = "linux")]
use std::fs::{self, File};
#[cfg(target_os = "linux")]
use std::io::Write;
use std::path::PathBuf;
#[cfg(target_os = "linux")]
use std::process::{Command, Stdio};
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
#[cfg(target_os = "linux")]
use sha2::{Digest, Sha256};

#[cfg(target_os = "linux")]
mod child_watch;

use crate::ocore::native_ir::{NativeModule, Operand, Operation, Terminator, Type};
use crate::ocore::Target;
use crate::value::{ONumber, OValue};
#[cfg(target_os = "linux")]
pub(crate) use child_watch::ChildWatch;

pub(crate) use crate::native_leaf_identity::digest;
pub use crate::native_leaf_identity::BUILTIN;
pub const SCHEMA: &str = "ocore-native-i64-leaf-v1";
/// Absolute path of the clang that assembles native leaves; when unset, the
/// absolute entries of PATH are searched.
pub const NATIVE_CLANG_ENV: &str = "O_NATIVE_CLANG";
/// Absolute path of the ld that links native leaves; when unset, the
/// absolute entries of PATH are searched.
pub const NATIVE_LD_ENV: &str = "O_NATIVE_LD";
/// Expected SHA-256 of the clang bytes; a different clang is refused.
pub const NATIVE_CLANG_SHA256_ENV: &str = "O_NATIVE_CLANG_SHA256";
/// Expected SHA-256 of the ld bytes; a different ld is refused.
pub const NATIVE_LD_SHA256_ENV: &str = "O_NATIVE_LD_SHA256";
/// The library path the native leaf tools get, when a pinned toolchain needs
/// one. the caller's own LD_LIBRARY_PATH never reaches them.
pub const NATIVE_TOOL_LIBRARY_PATH_ENV: &str = "O_NATIVE_TOOL_LIBRARY_PATH";
pub const PROFILE: &str = "linux-elf-i64-acyclic-v1";
const MAGIC: u64 = u64::from_le_bytes(*b"OCI64v1\0");

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Descriptor {
    schema: String,
    entry: String,
    module: NativeModule,
}

/// Canonical evidence for a generated leaf; no paths here confer authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeLeafManifest {
    pub profile: String,
    pub descriptor_sha256: String,
    pub module_sha256: String,
    pub entry: String,
    pub target: String,
    pub parameter_count: usize,
    pub adapter_executable_sha256: String,
    pub tool_environment_sha256: String,
    pub tool_working_directory: PathBuf,
    pub assembly_sha256: String,
    pub assembler: ToolIdentity,
    pub assembler_flags: Vec<String>,
    pub linker: ToolIdentity,
    pub linker_flags: Vec<String>,
    pub executable_sha256: String,
    pub executable_bytes: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolIdentity {
    pub invocation: PathBuf,
    pub executable_sha256: String,
}

struct Audited {
    descriptor: Descriptor,
    parameter_count: usize,
    module_sha256: String,
    target: Target,
    assembler_abi: Option<&'static str>,
}

fn symbol(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
        && name != "_start"
        && !name.starts_with("__ostadix_leaf_")
}

fn audit(text: &str) -> Result<Audited> {
    let descriptor: Descriptor =
        serde_json::from_str(text).context("decode static native leaf descriptor")?;
    if descriptor.schema != SCHEMA {
        bail!("native leaf descriptor requires {SCHEMA}");
    }
    let module_bytes = descriptor
        .module
        .to_json()
        .map_err(|e| anyhow::anyhow!("{}", e.message))?;
    // Verify first; the additional whitelist establishes the adapter's closed
    // effect footprint, rather than mistaking structural IR validity for purity.
    let module =
        NativeModule::from_json(&module_bytes).map_err(|e| anyhow::anyhow!("{}", e.message))?;
    if !module.globals.is_empty() || !module.aliases.is_empty() || !module.comdats.is_empty() {
        bail!("native scalar leaf does not admit globals, aliases or COMDAT selection");
    }
    if !module.target.little_endian
        || module.target.pointer_bits != 64
        || !module.target.triple.split('-').any(|part| part == "linux")
        || module.target.tls_profile.is_some()
        || module.target.atomic_profile.is_some()
    {
        bail!("native scalar leaf requires the little-endian 64-bit Linux ELF profile");
    }
    let target = match module.target.triple.split('-').next() {
        Some("x86_64") => Target::X86_64UnknownNone,
        Some("aarch64") => Target::Aarch64UnknownNone,
        Some("riscv64") => Target::Riscv64UnknownNone,
        _ => bail!("unsupported native scalar leaf ISA"),
    };
    // Mirror the owned object driver's explicit assembler ABI selection.
    // Linux Clang's RV default is LP64D; the owned module default is LP64.
    let assembler_abi = match (target, module.target.abi.as_deref()) {
        (Target::Riscv64UnknownNone, None | Some("lp64")) => Some("lp64"),
        (Target::Riscv64UnknownNone, Some("lp64d")) => Some("lp64d"),
        (_, None) => None,
        _ => bail!("native leaf assembler ABI is unsupported for this ISA"),
    };
    let scalar = |ty: usize| matches!(module.types.get(ty), Some(Type::Int { bits: 1 | 64 }));
    let i64_type = |ty: usize| matches!(module.types.get(ty), Some(Type::Int { bits: 64 }));
    let operand = |operand: &Operand| -> Result<()> {
        match operand {
            Operand::Value { .. } => Ok(()),
            Operand::Int { ty, .. } if scalar(*ty) => Ok(()),
            _ => bail!("native scalar leaf operand is outside the integer SSA profile"),
        }
    };
    let mut parameter_count = None;
    for function in &module.functions {
        // The importer retains the original compiler declaration when it
        // lowers llvm.trap to Operation::Trap. Structural verification above
        // checks its exact signature; it is metadata, never an external call.
        if function.name == "llvm.trap"
            && function.intrinsic.as_deref() == Some("llvm.trap")
            && function.entry.is_none()
            && function.blocks.is_empty()
            && function.signature.params.is_empty()
            && matches!(
                module.types.get(function.signature.result),
                Some(Type::Void)
            )
        {
            continue;
        }
        if !symbol(&function.name)
            || function.entry.is_none()
            || function.intrinsic.is_some()
            || function.exception_handling.is_some()
            || function.managed_method.is_some()
            || function.comdat.is_some()
            || function.linkage != "external"
            || function.signature.abi != "c"
            || function.signature.variadic
            || function.signature.return_storage.is_some()
            || !i64_type(function.signature.result)
            || !function.signature.params.iter().all(|ty| i64_type(*ty))
        {
            bail!("native scalar leaf requires defined external C-ABI i64 functions without runtime hooks");
        }
        if function.name == descriptor.entry {
            parameter_count = Some(function.params.len());
        }
        let mut positions = BTreeMap::new();
        for (index, block) in function.blocks.iter().enumerate() {
            positions.insert(block.id, index);
        }
        let mut successors = vec![Vec::new(); function.blocks.len()];
        let mut incoming = vec![0usize; function.blocks.len()];
        for (index, block) in function.blocks.iter().enumerate() {
            for instruction in &block.instructions {
                if instruction.result.is_some_and(|result| !scalar(result.ty)) {
                    bail!("native scalar leaf SSA values must be i1 or i64");
                }
                match &instruction.operation {
                    Operation::Trap {} => {}
                    Operation::Binary { lhs, rhs, .. }
                    | Operation::ICmp { lhs, rhs, .. }
                    | Operation::IntegerMinMax { lhs, rhs, .. } => {
                        operand(lhs)?;
                        operand(rhs)?;
                    }
                    Operation::Cast { value, .. } | Operation::Freeze { value } => operand(value)?,
                    Operation::Select {
                        condition,
                        on_true,
                        on_false,
                    } => {
                        operand(condition)?;
                        operand(on_true)?;
                        operand(on_false)?;
                    }
                    Operation::Phi { incoming } => {
                        for item in incoming {
                            operand(&item.value)?;
                        }
                    }
                    _ => bail!(
                        "native scalar leaf forbids memory, calls and external-effect instructions"
                    ),
                }
            }
            let mut edge = |target| -> Result<()> {
                let next = *positions
                    .get(&target)
                    .context("native leaf successor is absent")?;
                successors[index].push(next);
                incoming[next] = incoming[next]
                    .checked_add(1)
                    .context("native leaf CFG indegree overflow")?;
                Ok(())
            };
            match &block.terminator {
                Terminator::Return { value: Some(value) } => operand(value)?,
                Terminator::Jump { target } => edge(*target)?,
                Terminator::Branch {
                    condition,
                    on_true,
                    on_false,
                } => {
                    operand(condition)?;
                    edge(*on_true)?;
                    edge(*on_false)?;
                }
                Terminator::Switch {
                    condition,
                    default,
                    cases,
                } => {
                    operand(condition)?;
                    edge(*default)?;
                    for case in cases {
                        operand(&case.value)?;
                        edge(case.target)?;
                    }
                }
                Terminator::Unreachable => {}
                _ => {
                    bail!("native scalar leaf forbids exception and non-scalar return terminators")
                }
            }
        }
        // Iterative Kahn traversal includes unreachable source blocks: no
        // accepted function or branch is silently omitted to obtain purity.
        let mut ready: VecDeque<_> = incoming
            .iter()
            .enumerate()
            .filter_map(|(i, n)| (*n == 0).then_some(i))
            .collect();
        let mut visited = 0usize;
        while let Some(index) = ready.pop_front() {
            visited += 1;
            for &next in &successors[index] {
                incoming[next] -= 1;
                if incoming[next] == 0 {
                    ready.push_back(next);
                }
            }
        }
        if visited != function.blocks.len() {
            bail!("native scalar leaf requires acyclic control flow");
        }
    }
    let parameter_count =
        parameter_count.context("native scalar leaf entry is not a defined function")?;
    Ok(Audited {
        descriptor,
        parameter_count,
        module_sha256: digest(&module_bytes),
        target,
        assembler_abi,
    })
}

pub(crate) fn validate_descriptor(text: &str, arity: usize) -> Result<()> {
    let audited = audit(text)?;
    if audited.parameter_count != arity {
        bail!("native scalar leaf argument count differs from its C signature");
    }
    Ok(())
}

/// The trusted protocol wrapper has no libc, dynamic loader or foreign runtime.
/// It reads one exact frame to EOF, calls the audited C-ABI entry, writes one
/// exact response and exits. All integer argument counts use the platform ABI,
/// including stack arguments; checked arithmetic detects measured size failure.
fn wrapper(target: Target, entry: &str, arity: usize) -> Result<String> {
    let registers = if target == Target::X86_64UnknownNone {
        6
    } else {
        8
    };
    let stack = arity
        .saturating_sub(registers)
        .checked_mul(8)
        .context("native leaf stack size overflow")?;
    let stack = stack
        .checked_add(15)
        .context("native leaf stack alignment overflow")?
        & !15;
    let input = arity
        .checked_mul(8)
        .and_then(|n| n.checked_add(8))
        .context("native leaf input size overflow")?;
    let input_offset = stack
        .checked_add(16)
        .context("native leaf frame overflow")?;
    let total = input_offset
        .checked_add(input)
        .and_then(|n| n.checked_add(15))
        .context("native leaf frame overflow")?
        & !15;
    let mut out = String::from("\n.text\n.globl _start\n_start:\n");
    // A deliberate trap is a value failure, not authority to publish a core
    // file or invoke a host core-dump collector. Set non-dumpable after exec
    // (exec would reset a pre-exec PR_SET_DUMPABLE setting).
    out.push_str(match target {
        Target::X86_64UnknownNone => {
            "mov eax,157\nmov edi,4\nxor esi,esi\nsyscall\ntest rax,rax\njne .Lostadix_leaf_fail\n"
        }
        Target::Aarch64UnknownNone => {
            "mov x0,#4\nmov x1,#0\nmov x8,#167\nsvc #0\ncbnz x0,.Lostadix_leaf_fail\n"
        }
        Target::Riscv64UnknownNone => {
            "li a0,4\nli a1,0\nli a7,167\necall\nbnez a0,.Lostadix_leaf_fail\n"
        }
    });
    match target {
        Target::X86_64UnknownNone => {
            out.push_str(&format!(".intel_syntax noprefix\nmovabs rax, {total}\nsub rsp, rax\nmov r12, rsp\nmovabs rax, {input_offset}\nadd r12, rax\nmov r13, r12\nmovabs r14, {input}\n.Lostadix_leaf_read:\nxor eax,eax\nxor edi,edi\nmov rsi,r13\nmov rdx,r14\nsyscall\ncmp rax,-4\nje .Lostadix_leaf_read\ntest rax,rax\njle .Lostadix_leaf_fail\nadd r13,rax\nsub r14,rax\njne .Lostadix_leaf_read\n.Lostadix_leaf_eof:\nxor eax,eax\nxor edi,edi\nmov rsi,rsp\nmov edx,1\nsyscall\ncmp rax,-4\nje .Lostadix_leaf_eof\ntest rax,rax\njne .Lostadix_leaf_fail\nmovabs rax,{MAGIC}\ncmp [r12],rax\njne .Lostadix_leaf_fail\n"));
            for index in registers..arity {
                out.push_str(&format!(
                    "movabs rax,{}\nmov r10,[r12+rax]\nmovabs rax,{}\nmov [rsp+rax],r10\n",
                    8 + index * 8,
                    (index - registers) * 8
                ));
            }
            for (index, reg) in ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
                .iter()
                .take(arity)
                .enumerate()
            {
                out.push_str(&format!(
                    "movabs rax,{}\nmov {reg},[r12+rax]\n",
                    8 + index * 8
                ));
            }
            out.push_str(&format!("call {entry}\nmov r13,rsp\nmovabs rdx,{stack}\nadd r13,rdx\nmov [r13+8],rax\nmovabs rax,{MAGIC}\nmov [r13],rax\nmov r14d,16\n.Lostadix_leaf_write:\nmov eax,1\nmov edi,1\nmov rsi,r13\nmov rdx,r14\nsyscall\ncmp rax,-4\nje .Lostadix_leaf_write\ntest rax,rax\njle .Lostadix_leaf_fail\nadd r13,rax\nsub r14,rax\njne .Lostadix_leaf_write\nxor edi,edi\njmp .Lostadix_leaf_exit\n.Lostadix_leaf_fail:\nmov edi,74\n.Lostadix_leaf_exit:\nmov eax,60\nsyscall\nud2\n.section .note.GNU-stack,\"\",@progbits\n"));
        }
        Target::Aarch64UnknownNone => {
            fn imm(out: &mut String, reg: &str, value: u64) {
                out.push_str(&format!("movz {reg},#{}\n", value & 65535));
                for shift in [16, 32, 48] {
                    if (value >> shift) & 65535 != 0 {
                        out.push_str(&format!(
                            "movk {reg},#{},lsl #{shift}\n",
                            (value >> shift) & 65535
                        ));
                    }
                }
            }
            imm(&mut out, "x9", total as u64);
            out.push_str("sub sp,sp,x9\nmov x19,sp\n");
            imm(&mut out, "x9", input_offset as u64);
            out.push_str("add x19,x19,x9\nmov x20,x19\n");
            imm(&mut out, "x21", input as u64);
            out.push_str(".Lostadix_leaf_read:\nmov x0,#0\nmov x1,x20\nmov x2,x21\nmov x8,#63\nsvc #0\ncmn x0,#4\nb.eq .Lostadix_leaf_read\ncmp x0,#0\nb.le .Lostadix_leaf_fail\nadd x20,x20,x0\nsubs x21,x21,x0\nb.ne .Lostadix_leaf_read\n.Lostadix_leaf_eof:\nmov x0,#0\nmov x1,sp\nmov x2,#1\nmov x8,#63\nsvc #0\ncmn x0,#4\nb.eq .Lostadix_leaf_eof\ncbnz x0,.Lostadix_leaf_fail\nldr x10,[x19]\n");
            imm(&mut out, "x9", MAGIC);
            out.push_str("cmp x10,x9\nb.ne .Lostadix_leaf_fail\n");
            for index in registers..arity {
                imm(&mut out, "x9", (8 + index * 8) as u64);
                out.push_str("ldr x10,[x19,x9]\n");
                imm(&mut out, "x9", ((index - registers) * 8) as u64);
                out.push_str("str x10,[sp,x9]\n");
            }
            for index in 0..arity.min(registers) {
                imm(&mut out, "x9", (8 + index * 8) as u64);
                out.push_str(&format!("ldr x{index},[x19,x9]\n"));
            }
            out.push_str(&format!("bl {entry}\nmov x20,sp\n"));
            imm(&mut out, "x9", stack as u64);
            out.push_str("add x20,x20,x9\nstr x0,[x20,#8]\n");
            imm(&mut out, "x9", MAGIC);
            out.push_str("str x9,[x20]\nmov x21,#16\n.Lostadix_leaf_write:\nmov x0,#1\nmov x1,x20\nmov x2,x21\nmov x8,#64\nsvc #0\ncmn x0,#4\nb.eq .Lostadix_leaf_write\ncmp x0,#0\nb.le .Lostadix_leaf_fail\nadd x20,x20,x0\nsubs x21,x21,x0\nb.ne .Lostadix_leaf_write\nmov x0,#0\nb .Lostadix_leaf_exit\n.Lostadix_leaf_fail:\nmov x0,#74\n.Lostadix_leaf_exit:\nmov x8,#93\nsvc #0\nbrk #0\n.section .note.GNU-stack,\"\",@progbits\n");
        }
        Target::Riscv64UnknownNone => {
            out.push_str(&format!(".option norelax\nli t0,{total}\nsub sp,sp,t0\nli t0,{input_offset}\nadd s0,sp,t0\nmv s1,s0\nli s2,{input}\n.Lostadix_leaf_read:\nli a0,0\nmv a1,s1\nmv a2,s2\nli a7,63\necall\nli t0,-4\nbeq a0,t0,.Lostadix_leaf_read\nblez a0,.Lostadix_leaf_fail\nadd s1,s1,a0\nsub s2,s2,a0\nbnez s2,.Lostadix_leaf_read\n.Lostadix_leaf_eof:\nli a0,0\nmv a1,sp\nli a2,1\nli a7,63\necall\nli t0,-4\nbeq a0,t0,.Lostadix_leaf_eof\nbnez a0,.Lostadix_leaf_fail\nld t1,0(s0)\nli t0,{MAGIC}\nbne t0,t1,.Lostadix_leaf_fail\n"));
            for index in registers..arity {
                out.push_str(&format!(
                    "li t0,{}\nadd t0,s0,t0\nld t1,0(t0)\nli t0,{}\nadd t0,sp,t0\nsd t1,0(t0)\n",
                    8 + index * 8,
                    (index - registers) * 8
                ));
            }
            for index in 0..arity.min(registers) {
                out.push_str(&format!(
                    "li t0,{}\nadd t0,s0,t0\nld a{index},0(t0)\n",
                    8 + index * 8
                ));
            }
            out.push_str(&format!("call {entry}\nli t0,{stack}\nadd s1,sp,t0\nsd a0,8(s1)\nli t0,{MAGIC}\nsd t0,0(s1)\nli s2,16\n.Lostadix_leaf_write:\nli a0,1\nmv a1,s1\nmv a2,s2\nli a7,64\necall\nli t0,-4\nbeq a0,t0,.Lostadix_leaf_write\nblez a0,.Lostadix_leaf_fail\nadd s1,s1,a0\nsub s2,s2,a0\nbnez s2,.Lostadix_leaf_write\nli a0,0\nj .Lostadix_leaf_exit\n.Lostadix_leaf_fail:\nli a0,74\n.Lostadix_leaf_exit:\nli a7,93\necall\nunimp\n.section .note.GNU-stack,\"\",@progbits\n"));
        }
    }
    Ok(out)
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct SealedImage {
    file: File,
    sha256: String,
    bytes: usize,
}

#[cfg(target_os = "linux")]
impl SealedImage {
    fn new(bytes: &[u8]) -> Result<Self> {
        use std::os::fd::{AsRawFd, FromRawFd};
        let fd = unsafe {
            libc::memfd_create(
                c"ostadix-native-i64".as_ptr(),
                libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error()).context("create sealed native image");
        }
        let mut file = unsafe { File::from_raw_fd(fd) };
        file.write_all(bytes)?;
        if unsafe { libc::fchmod(fd, 0o500) } != 0
            || unsafe {
                libc::fcntl(
                    file.as_raw_fd(),
                    libc::F_ADD_SEALS,
                    libc::F_SEAL_WRITE
                        | libc::F_SEAL_GROW
                        | libc::F_SEAL_SHRINK
                        | libc::F_SEAL_SEAL,
                )
            } < 0
        {
            return Err(std::io::Error::last_os_error()).context("seal native image");
        }
        Ok(Self {
            file,
            sha256: digest(bytes),
            bytes: bytes.len(),
        })
    }
    fn verify(&self) -> Result<()> {
        use std::os::fd::AsRawFd;
        let seals = unsafe { libc::fcntl(self.file.as_raw_fd(), libc::F_GET_SEALS) };
        let expected =
            libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
        if seals < 0
            || seals & expected != expected
            || self.file.metadata()?.len() != self.bytes as u64
        {
            bail!("native image lost its immutable lease");
        }
        Ok(())
    }
    fn command(&self) -> Result<Command> {
        use std::os::fd::AsRawFd;
        self.verify()?;
        // The parent's sealed descriptor survives Command's pre-exec fd
        // cleanup. The kernel opens this exact immutable inode, never a mutable
        // artifact pathname; no fallback path execution is permitted.
        Ok(Command::new(format!(
            "/proc/{}/fd/{}",
            std::process::id(),
            self.file.as_raw_fd()
        )))
    }
}

#[derive(Debug)]
pub(crate) struct PreparedLeaf {
    pub manifest: NativeLeafManifest,
    manifest_binding: String,
    #[cfg(target_os = "linux")]
    image: SealedImage,
}

impl PreparedLeaf {
    pub(crate) fn verify(&self) -> Result<()> {
        if digest(&serde_json::to_vec(&self.manifest)?) != self.manifest_binding {
            bail!("native leaf manifest changed after construction");
        }
        #[cfg(target_os = "linux")]
        {
            self.image.verify()?;
            if self.image.sha256 != self.manifest.executable_sha256 {
                bail!("native leaf executable binding differs from its lease");
            }
            Ok(())
        }
        #[cfg(not(target_os = "linux"))]
        {
            bail!("native scalar leaf execution requires Linux sealed ELF leases")
        }
    }
    /// Run the sealed leaf under the process-wide knobs, with no request
    /// cancellation; tests use it, the executor passes its own watch.
    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn execute(&self, arguments: &[i64]) -> Result<OValue> {
        self.execute_watched(arguments, &ChildWatch::from_knobs(None)?)
    }

    /// Run the sealed leaf under `watch`: the opt-in step limit and the
    /// request's cancellation kill its process group, and a long run warns.
    #[cfg(target_os = "linux")]
    pub(crate) fn execute_watched(
        &self,
        arguments: &[i64],
        watch: &ChildWatch<'_>,
    ) -> Result<OValue> {
        if arguments.len() != self.manifest.parameter_count {
            bail!("native leaf argument count mismatch");
        }
        #[cfg(target_os = "linux")]
        {
            self.verify()?;
            use std::os::unix::process::CommandExt;
            let mut child = self
                .image
                .command()?
                .env_clear()
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .process_group(0)
                .spawn()
                .context("launch admitted owned native scalar leaf")?;
            let stdout = child
                .stdout
                .take()
                .context("native leaf stdout unavailable")?;
            let reader = child_watch::capture(stdout);
            let write = (|| -> Result<()> {
                let mut input = child
                    .stdin
                    .take()
                    .context("native leaf stdin unavailable")?;
                input.write_all(&MAGIC.to_le_bytes())?;
                for argument in arguments {
                    input.write_all(&argument.to_le_bytes())?;
                }
                Ok(())
            })();
            if let Err(error) = write {
                // SAFETY: killpg only signals the leaf's own unreaped group.
                unsafe {
                    libc::killpg(child.id() as libc::pid_t, libc::SIGKILL);
                }
                let _ = child.wait();
                return Err(error).context("send native scalar frame");
            }
            let status = child_watch::wait(&mut child, "leaf", watch)?;
            let stdout = child_watch::captured(reader, "leaf stdout")?;
            if !status.success() {
                bail!("owned native scalar leaf failed: {status}");
            }
            if stdout.len() != 16 || stdout[..8] != MAGIC.to_le_bytes() {
                bail!("owned native scalar leaf returned an invalid exact frame");
            }
            let value =
                i64::from_le_bytes(stdout[8..].try_into().expect("checked response length"));
            crate::lifecycle_trace::lifecycle_trace(
                "native_leaf.executed",
                format!(
                    "descriptor={} executable={} profile={}",
                    self.manifest.descriptor_sha256, self.manifest.executable_sha256, PROFILE
                ),
            );
            Ok(OValue::big_int(value))
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub(crate) fn execute(&self, arguments: &[i64]) -> Result<OValue> {
        if arguments.len() != self.manifest.parameter_count {
            bail!("native leaf argument count mismatch");
        }
        bail!("native scalar leaf execution requires Linux")
    }
}

pub(crate) fn argument(value: &OValue) -> Result<i64> {
    use num_traits::ToPrimitive;
    match value {
        OValue::Number {
            v: ONumber::Int { v },
        } => v
            .to_i64()
            .context("native scalar argument exceeds signed i64"),
        OValue::Text { v } => {
            let parsed: i64 = v
                .utf8
                .parse()
                .context("native scalar text argument must be a signed i64 decimal")?;
            if parsed.to_string() != v.utf8 {
                bail!("native scalar text argument must be canonical signed decimal");
            }
            Ok(parsed)
        }
        _ => bail!("native scalar argument must be an integer or canonical signed decimal text"),
    }
}

#[cfg(target_os = "linux")]
struct BuildDirectory(PathBuf);
#[cfg(target_os = "linux")]
impl BuildDirectory {
    fn new() -> Result<Self> {
        use std::os::unix::fs::DirBuilderExt;
        loop {
            let mut random = [0u8; 16];
            getrandom::fill(&mut random).map_err(|e| anyhow::anyhow!("{e}"))?;
            let path =
                std::env::temp_dir().join(format!("ostadix-native-i64-{}", hex::encode(random)));
            let path = if path.is_absolute() {
                path
            } else {
                std::env::current_dir()?.join(path)
            };
            match fs::DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
        }
    }
}
#[cfg(target_os = "linux")]
impl Drop for BuildDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

pub(crate) fn prepare(text: &str) -> Result<Arc<PreparedLeaf>> {
    let audited = audit(text)?;
    #[cfg(target_os = "linux")]
    {
        let host = match std::env::consts::ARCH {
            "x86_64" => Target::X86_64UnknownNone,
            "aarch64" => Target::Aarch64UnknownNone,
            "riscv64" => Target::Riscv64UnknownNone,
            _ => bail!("native scalar host ISA is unsupported"),
        };
        if host != audited.target {
            bail!("native scalar leaf target must match the Linux host ISA");
        }
        let tool_working_directory =
            std::env::current_dir().context("capture native tool working directory")?;
        let tool_search_path = std::env::var_os("PATH");
        fn tool(
            name: &str,
            pin_env: &str,
            sha_env: &str,
            search_path: &Option<std::ffi::OsString>,
        ) -> Result<(ToolIdentity, SealedImage)> {
            let invocation = locate_tool(name, pin_env, std::env::var_os(pin_env), search_path)?;
            let bytes = fs::read(&invocation)
                .with_context(|| format!("read native leaf {name} {}", invocation.display()))?;
            if !bytes.starts_with(b"\x7fELF") {
                bail!("native leaf {name} must be an ELF executable, not a script launcher");
            }
            // the sealed copy is what runs, so checking these bytes checks it.
            check_tool_sha256(name, sha_env, std::env::var(sha_env).ok(), &digest(&bytes))?;
            let image = SealedImage::new(&bytes)?;
            Ok((
                ToolIdentity {
                    invocation,
                    executable_sha256: image.sha256.clone(),
                },
                image,
            ))
        }
        let tool_library_path = tool_library_path(std::env::var_os(NATIVE_TOOL_LIBRARY_PATH_ENV))?;
        fn tool_environment(command: &mut Command, library_path: &Option<std::ffi::OsString>) {
            command.env_clear().env("LC_ALL", "C");
            if let Some(path) = library_path {
                command.env("LD_LIBRARY_PATH", path);
            }
        }
        fn run(
            mut command: Command,
            label: &str,
            library_path: &Option<std::ffi::OsString>,
            cwd: &std::path::Path,
            build: &std::path::Path,
            invocation: &std::path::Path,
        ) -> Result<()> {
            use std::os::unix::process::CommandExt;
            tool_environment(&mut command, library_path);
            let mut child = command
                .current_dir(cwd)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .process_group(0)
                .spawn()
                .context("launch pinned native assembly tool")?;
            let stderr = child
                .stderr
                .take()
                .context("native tool stderr unavailable")?;
            let reader = child_watch::capture(stderr);
            // admission has no request token; the opt-in limit still applies.
            let status = child_watch::wait(&mut child, label, &ChildWatch::from_knobs(None)?)?;
            let stderr = child_watch::captured(reader, "tool stderr")?;
            if !status.success() {
                bail!(
                    "trusted native assembly/link failed ({status}): {}",
                    scrub_tool_text(&stderr, build, invocation, cwd)
                );
            }
            Ok(())
        }
        let (assembler, assembler_image) = tool(
            "clang",
            NATIVE_CLANG_ENV,
            NATIVE_CLANG_SHA256_ENV,
            &tool_search_path,
        )?;
        let (linker, linker_image) =
            tool("ld", NATIVE_LD_ENV, NATIVE_LD_SHA256_ENV, &tool_search_path)?;
        let mut assembly =
            crate::ocore::native_codegen::emit(&audited.descriptor.module, audited.target)
                .map_err(|e| anyhow::anyhow!("{}", e.message))?;
        assembly.push_str(&wrapper(
            audited.target,
            &audited.descriptor.entry,
            audited.parameter_count,
        )?);
        let directory = BuildDirectory::new()?;
        let source = directory.0.join("leaf.s");
        let object = directory.0.join("leaf.o");
        let executable = directory.0.join("leaf.elf");
        fs::write(&source, &assembly)?;
        use std::os::unix::process::CommandExt as _;
        let mut assembler_flags = vec![
            "--no-default-config".to_string(),
            "-fintegrated-as".into(),
            "-c".into(),
            "-x".into(),
            "assembler".into(),
            "-target".into(),
            audited.descriptor.module.target.triple.clone(),
        ];
        if let Some(abi) = audited.assembler_abi {
            assembler_flags.extend(["-march=rv64gc".into(), format!("-mabi={abi}")]);
        }
        let mut assemble = assembler_image.command()?;
        assemble
            .arg0(&assembler.invocation)
            .args(&assembler_flags)
            .arg(&source)
            .arg("-o")
            .arg(&object);
        run(
            assemble,
            "clang",
            &tool_library_path,
            &tool_working_directory,
            &directory.0,
            &assembler.invocation,
        )?;
        let mut link = linker_image.command()?;
        let linker_flags = vec![
            "-static".to_string(),
            "--build-id=none".into(),
            "-e".into(),
            "_start".into(),
        ];
        link.arg0(&linker.invocation)
            .args(&linker_flags)
            .arg(&object)
            .arg("-o")
            .arg(&executable);
        run(
            link,
            "ld",
            &tool_library_path,
            &tool_working_directory,
            &directory.0,
            &linker.invocation,
        )?;
        let bytes = fs::read(&executable)?;
        if !bytes.starts_with(b"\x7fELF") {
            bail!("native linker did not produce ELF");
        }
        let image = SealedImage::new(&bytes)?;
        let environment_sha256 = tool_environment_sha256(tool_library_path.as_deref());
        let manifest = NativeLeafManifest {
            profile: PROFILE.into(),
            descriptor_sha256: digest(text.as_bytes()),
            module_sha256: audited.module_sha256,
            entry: audited.descriptor.entry,
            target: audited.descriptor.module.target.triple,
            parameter_count: audited.parameter_count,
            adapter_executable_sha256: digest(&fs::read("/proc/self/exe")?),
            tool_environment_sha256: environment_sha256,
            tool_working_directory,
            assembly_sha256: digest(assembly.as_bytes()),
            assembler,
            assembler_flags,
            linker,
            linker_flags,
            executable_sha256: image.sha256.clone(),
            executable_bytes: image.bytes,
        };
        crate::lifecycle_trace::lifecycle_trace(
            "native_leaf.prepared",
            serde_json::to_string(&manifest)?,
        );
        let manifest_binding = digest(&serde_json::to_vec(&manifest)?);
        Ok(Arc::new(PreparedLeaf {
            manifest,
            manifest_binding,
            image,
        }))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = audited;
        bail!("native scalar leaf execution requires Linux sealed ELF leases")
    }
}

// ############################################################################
// tool resolution
// ############################################################################

/// The absolute path of native leaf tool `name`: the pinned path in `pin_env`
/// when set, else the first absolute PATH entry holding an executable file.
/// why absolute only: an empty or relative PATH entry resolves against the
/// caller's cwd, so running O inside an untrusted checkout would run its
/// `./clang`. such entries are skipped, never consulted.
#[cfg(target_os = "linux")]
fn locate_tool(
    name: &str,
    pin_env: &str,
    pin: Option<std::ffi::OsString>,
    search_path: &Option<std::ffi::OsString>,
) -> Result<PathBuf> {
    use std::os::unix::fs::PermissionsExt as _;
    let runnable = |path: &std::path::Path| {
        fs::metadata(path)
            .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
    };
    if let Some(pin) = pin {
        let path = PathBuf::from(pin);
        if !path.is_absolute() {
            bail!(
                "{pin_env} must be an absolute path to {name}, got {}",
                path.display()
            );
        }
        if !runnable(&path) {
            bail!(
                "{pin_env} names {}, which is not an executable file",
                path.display()
            );
        }
        return Ok(path);
    }
    for entry in search_path.iter().flat_map(std::env::split_paths) {
        if !entry.is_absolute() {
            continue;
        }
        let candidate = entry.join(name);
        if runnable(&candidate) {
            return Ok(candidate);
        }
    }
    bail!(
        "locate trusted native leaf {name}: {pin_env} is unset and no absolute PATH \
         entry has an executable {name}"
    )
}

/// The tools' LD_LIBRARY_PATH: only what `O_NATIVE_TOOL_LIBRARY_PATH` sets,
/// and only absolute entries, so a hostile library dir in the caller's own
/// LD_LIBRARY_PATH (or a relative entry resolved against the cwd) cannot
/// load into the trusted assembler or linker.
fn tool_library_path(configured: Option<std::ffi::OsString>) -> Result<Option<std::ffi::OsString>> {
    let Some(configured) = configured else {
        return Ok(None);
    };
    if let Some(entry) = std::env::split_paths(&configured).find(|entry| !entry.is_absolute()) {
        bail!(
            "{NATIVE_TOOL_LIBRARY_PATH_ENV} entries must be absolute, got {:?}",
            entry.display().to_string()
        );
    }
    Ok(Some(configured))
}

/// Refuse tool bytes whose SHA-256 differs from the pin in `sha_env`. a pin
/// that is not 64 lowercase hex digits is an error, not "no pin".
fn check_tool_sha256(name: &str, sha_env: &str, pin: Option<String>, actual: &str) -> Result<()> {
    let Some(pin) = pin else {
        return Ok(());
    };
    if pin.len() != 64
        || !pin
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        bail!("{sha_env} must be 64 lowercase hex digits, got {pin:?}");
    }
    if pin != actual {
        bail!("native leaf {name} has SHA-256 {actual}, but {sha_env} pins {pin}; refusing it");
    }
    Ok(())
}

/// Tool stderr with the private build directory replaced by a fixed name:
/// errors never carry temp paths, and the text stays the same across runs.
#[cfg(target_os = "linux")]
fn scrub_tool_text(
    stderr: &[u8],
    build: &std::path::Path,
    invocation: &std::path::Path,
    cwd: &std::path::Path,
) -> String {
    let mut text = String::from_utf8_lossy(stderr).into_owned();
    text = text.replace(&*build.to_string_lossy(), "<native build directory>");
    // GNU ld prefixes its messages with argv0, the tool's absolute path.
    if let Some(name) = invocation.file_name() {
        text = text.replace(&*invocation.to_string_lossy(), &name.to_string_lossy());
    }
    let cwd = cwd.to_string_lossy();
    if cwd.len() > 1 {
        text = text.replace(&*cwd, "<tool working directory>");
    }
    text
}

#[cfg(target_os = "linux")]
fn tool_environment_sha256(library_path: Option<&std::ffi::OsStr>) -> String {
    use std::os::unix::ffi::OsStrExt;
    let mut hash = Sha256::new();
    hash.update(b"ostadix-native-leaf-tool-environment/v1\0LC_ALL\0C\0LD_LIBRARY_PATH\0");
    if let Some(value) = library_path {
        hash.update([1]);
        hash.update((value.as_bytes().len() as u64).to_be_bytes());
        hash.update(value.as_bytes());
    } else {
        hash.update([0]);
    }
    hex::encode(hash.finalize())
}

#[cfg(test)]
#[path = "native_leaf_tests.rs"]
mod independent_tests;

pub(crate) fn validate_manifests(manifests: &[NativeLeafManifest]) -> Result<()> {
    let mut previous = None;
    for manifest in manifests {
        if manifest.profile != PROFILE
            || manifest.executable_bytes == 0
            || !symbol(&manifest.entry)
            || !manifest.tool_working_directory.is_absolute()
            || !manifest.assembler.invocation.is_absolute()
            || !manifest.linker.invocation.is_absolute()
            || previous.is_some_and(|key: &str| key >= manifest.descriptor_sha256.as_str())
        {
            bail!("invalid native leaf manifest profile, identity or ordering");
        }
        for sha in [
            &manifest.descriptor_sha256,
            &manifest.module_sha256,
            &manifest.adapter_executable_sha256,
            &manifest.tool_environment_sha256,
            &manifest.assembly_sha256,
            &manifest.assembler.executable_sha256,
            &manifest.linker.executable_sha256,
            &manifest.executable_sha256,
        ] {
            if sha.len() != 64
                || !sha
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                bail!("invalid native leaf SHA-256 binding");
            }
        }
        previous = Some(manifest.descriptor_sha256.as_str());
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn test_descriptor(arity: usize, trap: bool) -> String {
    use serde_json::json;
    let isa = std::env::consts::ARCH;
    let value = |id| json!({"kind":"value","id":id});
    let mut instructions = Vec::new();
    let result = if trap {
        instructions.push(json!({"result":null,"operation":{"op":"trap"}}));
        json!({"op":"unreachable"})
    } else {
        let mut current = json!({"kind":"int","ty":1,"bits":"1"});
        for id in 0..arity {
            instructions.push(json!({"result":{"id":arity+id,"ty":1},"operation":{"op":"binary","kind":"add","lhs":current,"rhs":value(id),"flags":[]}}));
            current = value(arity + id);
        }
        json!({"op":"return","value":current})
    };
    let signature = |params: Vec<usize>, result| json!({"params":params,"result":result,"abi":"c","variadic":false});
    let mut functions = vec![
        json!({"name":"native_add","linkage":"external","signature":signature(vec![1;arity],1),"params":(0..arity).map(|id|json!({"id":id,"ty":1})).collect::<Vec<_>>(),"entry":0,"blocks":[{"id":0,"instructions":instructions,"terminator":result}]}),
    ];
    if trap {
        functions.push(json!({"name":"llvm.trap","linkage":"external","signature":signature(Vec::new(),0),"params":[],"entry":null,"blocks":[],"intrinsic":"llvm.trap"}));
    }
    json!({"schema":SCHEMA,"entry":"native_add","module":{"format":"ocore-native-module-v1","name":"graph-native-scalar-test","target":{"triple":format!("{isa}-unknown-linux-gnu"),"data_layout":"e-m:e-p:64:64-i64:64-i128:128-n8:16:32:64-S128","pointer_bits":64,"little_endian":true},"semantics":"llvm_defined_behavior_v1","types":[{"kind":"void"},{"kind":"int","bits":64},{"kind":"int","bits":1}],"globals":[],"functions":functions,"provenance":{"input_sha256":"0".repeat(64),"frontend":"native-leaf-regression","frontend_version":"1","importer":"regression-fixture","importer_version":"1","source_function_count":if trap {2}else{1},"source_global_count":0,"refinements":[]}}}).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_os = "linux")]
    #[test]
    fn tool_stderr_never_carries_local_paths() {
        let build = std::path::Path::new("/tmp/ostadix-native-i64-0123abcd");
        let ld = std::path::Path::new("/home/someone/.nix-profile/bin/ld");
        let cwd = std::path::Path::new("/home/someone/project");
        let stderr = b"/tmp/ostadix-native-i64-0123abcd/leaf.s:3:1: error: bad\n\
            /home/someone/.nix-profile/bin/ld: cannot open /home/someone/project/x\n";
        let text = scrub_tool_text(stderr, build, ld, cwd);
        assert_eq!(
            text,
            "<native build directory>/leaf.s:3:1: error: bad\n\
             ld: cannot open <tool working directory>/x\n"
        );
        assert!(!text.contains("/home/someone"), "{text}");
    }
    /// A private dir holding an executable stand-in named `name`.
    #[cfg(target_os = "linux")]
    fn fake_tool_dir(name: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt as _;
        let mut random = [0u8; 16];
        getrandom::fill(&mut random).unwrap();
        let dir = std::env::temp_dir().join(format!("o-native-tool-test-{}", hex::encode(random)));
        fs::create_dir(&dir).unwrap();
        let tool = dir.join(name);
        fs::write(&tool, b"\x7fELF").unwrap();
        fs::set_permissions(&tool, fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn tools_come_from_a_pin_or_absolute_path_entries_never_the_cwd() {
        let dir = fake_tool_dir("clang");
        // the same dir, spelled relative to the test's cwd.
        let cwd = std::env::current_dir().unwrap();
        let mut relative = PathBuf::new();
        for _ in cwd.components().skip(1) {
            relative.push("..");
        }
        relative.push(dir.strip_prefix("/").unwrap());
        assert!(relative.is_relative() && relative.join("clang").is_file());
        let path = |entries: &[&std::path::Path]| Some(std::env::join_paths(entries).unwrap());
        let empty = std::path::Path::new("");
        let dot = std::path::Path::new(".");
        // empty, dot and relative entries are never searched, even when they
        // hold the tool.
        let error = locate_tool(
            "clang",
            NATIVE_CLANG_ENV,
            None,
            &path(&[empty, dot, &relative]),
        )
        .unwrap_err();
        assert!(
            format!("{error:#}").contains("O_NATIVE_CLANG is unset"),
            "{error:#}"
        );
        assert_eq!(
            locate_tool(
                "clang",
                NATIVE_CLANG_ENV,
                None,
                &path(&[empty, &relative, &dir])
            )
            .unwrap(),
            dir.join("clang")
        );
        // a pin wins over PATH, must be absolute and must name an executable.
        let pinned = dir.join("clang");
        assert_eq!(
            locate_tool(
                "clang",
                NATIVE_CLANG_ENV,
                Some(pinned.clone().into()),
                &None
            )
            .unwrap(),
            pinned
        );
        let error = locate_tool(
            "clang",
            NATIVE_CLANG_ENV,
            Some(relative.join("clang").into()),
            &path(&[&dir]),
        )
        .unwrap_err();
        assert!(
            format!("{error:#}").contains("must be an absolute path"),
            "{error:#}"
        );
        let error = locate_tool(
            "clang",
            NATIVE_CLANG_ENV,
            Some(dir.join("missing").into()),
            &path(&[&dir]),
        )
        .unwrap_err();
        assert!(
            format!("{error:#}").contains("not an executable file"),
            "{error:#}"
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn tools_never_inherit_the_callers_library_path() {
        // the caller's LD_LIBRARY_PATH is not read at all; only the explicit
        // knob reaches the tools, and only with absolute entries.
        assert_eq!(tool_library_path(None).unwrap(), None);
        let configured = std::ffi::OsString::from("/opt/llvm/lib:/opt/llvm/lib64");
        assert_eq!(
            tool_library_path(Some(configured.clone())).unwrap(),
            Some(configured)
        );
        for relative in ["lib", "/opt/llvm/lib::/x", "./lib:/opt/llvm/lib"] {
            let error = tool_library_path(Some(relative.into())).unwrap_err();
            assert!(
                format!("{error:#}").contains("must be absolute"),
                "{relative}: {error:#}"
            );
        }
    }

    #[test]
    fn a_tool_whose_bytes_differ_from_its_pin_is_refused() {
        let actual = digest(b"clang bytes");
        check_tool_sha256("clang", NATIVE_CLANG_SHA256_ENV, None, &actual).unwrap();
        check_tool_sha256(
            "clang",
            NATIVE_CLANG_SHA256_ENV,
            Some(actual.clone()),
            &actual,
        )
        .unwrap();
        let other = digest(b"another clang");
        let error =
            check_tool_sha256("clang", NATIVE_CLANG_SHA256_ENV, Some(other), &actual).unwrap_err();
        assert!(format!("{error:#}").contains("refusing it"), "{error:#}");
        for malformed in ["", "abc", &actual.to_uppercase()] {
            let error = check_tool_sha256(
                "clang",
                NATIVE_CLANG_SHA256_ENV,
                Some(malformed.to_string()),
                &actual,
            )
            .unwrap_err();
            assert!(
                format!("{error:#}").contains("64 lowercase hex"),
                "{error:#}"
            );
        }
    }

    #[test]
    fn native_leaf_audits_every_function_and_rejects_cycles_and_supplied_code() {
        let good = test_descriptor(1, false);
        validate_descriptor(&good, 1).unwrap();
        assert!(validate_descriptor(&good, 2).is_err());
        let mut descriptor: serde_json::Value = serde_json::from_str(&good).unwrap();
        descriptor["executable"] = serde_json::json!("/tmp/supplied-elf");
        assert!(validate_descriptor(&descriptor.to_string(), 1).is_err());
        descriptor.as_object_mut().unwrap().remove("executable");
        descriptor["module"]["functions"][0]["blocks"][0]["terminator"] =
            serde_json::json!({"op":"jump","target":1});
        descriptor["module"]["functions"][0]["blocks"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({
                "id":1,"instructions":[],"terminator":{"op":"jump","target":1}
            }));
        let module: NativeModule = serde_json::from_value(descriptor["module"].clone()).unwrap();
        NativeModule::from_json(&module.to_json().unwrap()).unwrap();
        let error = validate_descriptor(&descriptor.to_string(), 1).unwrap_err();
        assert!(format!("{error:#}").contains("acyclic"), "{error:#}");
        let mut descriptor: serde_json::Value = serde_json::from_str(&good).unwrap();
        let mut external = descriptor["module"]["functions"][0].clone();
        external["name"] = serde_json::json!("unreachable_external");
        external["entry"] = serde_json::Value::Null;
        external["blocks"] = serde_json::json!([]);
        descriptor["module"]["functions"]
            .as_array_mut()
            .unwrap()
            .push(external);
        descriptor["module"]["provenance"]["source_function_count"] = serde_json::json!(2);
        assert!(
            validate_descriptor(&descriptor.to_string(), 1).is_err(),
            "unused externals must not disappear"
        );
    }
    #[test]
    fn native_leaf_wrappers_cover_all_scalar_stack_abis_without_count_gate() {
        for (isa, target) in [
            ("x86_64", Target::X86_64UnknownNone),
            ("aarch64", Target::Aarch64UnknownNone),
            ("riscv64", Target::Riscv64UnknownNone),
        ] {
            let mut descriptor: serde_json::Value =
                serde_json::from_str(&test_descriptor(12, false)).unwrap();
            descriptor["module"]["target"]["triple"] =
                serde_json::json!(format!("{isa}-unknown-linux-gnu"));
            let audited = audit(&descriptor.to_string()).unwrap();
            crate::ocore::native_codegen::emit(&audited.descriptor.module, target).unwrap();
            let wrapper = wrapper(target, "native_add", 12).unwrap();
            assert!(wrapper.contains("native_add"));
            assert!(wrapper.contains(".Lostadix_leaf_eof"));
            assert!(wrapper.contains(".Lostadix_leaf_write"));
        }
        validate_descriptor(&test_descriptor(600, false), 600).unwrap();
    }
    #[test]
    fn native_leaf_scalar_crossing_is_exact() {
        for value in [i64::MIN, 0, 42, i64::MAX] {
            assert_eq!(argument(&OValue::big_int(value)).unwrap(), value);
            assert_eq!(argument(&OValue::str_(value.to_string())).unwrap(), value);
        }
        for text in ["01", "+1", " 1", "1.0", "9223372036854775808"] {
            assert!(argument(&OValue::str_(text)).is_err());
        }
        assert!(argument(&OValue::Bool { v: true }).is_err());
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn native_leaf_runs_owned_sealed_code_with_stack_arguments_and_trap_failure() {
        let leaf = prepare(&test_descriptor(12, false)).unwrap();
        validate_manifests(std::slice::from_ref(&leaf.manifest)).unwrap();
        let arguments: Vec<i64> = (1..=12).collect();
        assert_eq!(argument(&leaf.execute(&arguments).unwrap()).unwrap(), 79);
        let mut writable = &leaf.image.file;
        assert!(
            writable.write_all(b"changed").is_err(),
            "sealed executable must reject mutation"
        );
        let trap = prepare(&test_descriptor(1, true)).unwrap();
        assert!(
            trap.execute(&[41]).is_err(),
            "trap must not publish a scalar result"
        );
    }
}
