/* Test-only Linux x86-64 child setup, not original implementation or provider.
   Run only as the already forked/posix_spawned owned child. No parent state. */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>
static _Noreturn void failed(const char *step){perror(step);syscall(SYS_exit,125);__builtin_unreachable();}
int main(int argc,char **argv){
#if !defined(__x86_64__)
#error the seccomp fallback reference is declared for real x86-64 only
#endif
 if(argc!=4){errno=EINVAL;failed("reference launcher argc");}
 fprintf(stderr,"owned-launcher pid=%ld ppid=%ld uid=%lu euid=%lu gid=%lu egid=%lu fallback=%s\n",(long)getpid(),(long)getppid(),(unsigned long)getuid(),(unsigned long)geteuid(),(unsigned long)getgid(),(unsigned long)getegid(),argv[1]);fflush(stderr);
 if(argv[1][0]=='1'&&!argv[1][1]){
  struct sock_filter code[]={
   BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,arch)),
   BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,AUDIT_ARCH_X86_64,1,0),
   BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_KILL_PROCESS),
   BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
   BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,__NR_exit_group,0,1),
   BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|ENOSYS),
   BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)
  };
  struct sock_fprog prog={.len=sizeof(code)/sizeof(code[0]),.filter=code};
  if(prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0))failed("owned child NO_NEW_PRIVS");
  if(syscall(SYS_seccomp,SECCOMP_SET_MODE_FILTER,0,&prog))failed("owned child seccomp exact231");
 }else if(argv[1][0]!='0'||argv[1][1]){errno=EINVAL;failed("invalid fallback profile");}
 execv(argv[2],argv+2);failed("owned child exec");
}
