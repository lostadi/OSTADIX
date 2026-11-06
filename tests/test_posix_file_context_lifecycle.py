"""Exercise actual PCB/AS/CSpace reuse beyond the file-context table size.

The underlying native carrier keeps the production registries, common file
service and original codec closure. Its five architecture hooks are replaced;
this is not a hardware/exec/process-launch or general POSIX qualification.
"""

import platform
from unittest.mock import patch
import unittest

from tests import test_posix_file_syscalls as BASE


LIFETIME = r'''
 extern uint64_t P(mark_reapable)(uint64_t),P(is_live)(uint64_t);
 extern int64_t K(retire_reaped_process)(uint64_t);
 extern int64_t _O_runtime__common__posix_namespace_files__retire(uint64_t,uint64_t,uint64_t);
 assert(K(retire_reaped_process)(0)==-22&&K(retire_reaped_process)(UINT64_C(0xdeadbeef))==-9);
 assert(K(retire_reaped_process)(p0)==-16); // A live owner must retain its high-water mark.
 assert(K(retire_reaped_process)(new_p1)==-16); // Exited is not fully reaped.
 int64_t sibling=open_path("/work/large");assert(sibling==3&&K(read)(sibling,(uintptr_t)dest,7)==7);
 uint64_t namespace_id=203,context_generation=1;
 for(unsigned cycle=0;cycle<64;cycle++){
  uint64_t dead=new_p1;
  assert(P(mark_reapable)(dead)==1&&P(begin_reap)(dead)==1);
  assert(A(destroy)(new_a1)==1&&M(drain_and_destroy_cspace)(new_c1)==1&&P(finalize_reap)(dead)==1);
  assert(!P(is_live)(dead));
  assert(_O_runtime__common__posix_namespace_files__retire(dead,namespace_id,context_generation+1)==-116);
  if(cycle==0){assert(K(retire_reaped_process)(dead)==0&&K(retire_reaped_process)(dead)==-9);}
  new_c1=CAP(create_cspace)(1);assert(new_c1&&M(set_quota_for_owner)(new_c1,8)==1);
  new_a1=A(create_native_for_owner)(new_c1);assert(new_a1);
  new_p1=P(install_for_owner)(1,200+cycle,domain,new_a1,new_c1,0xa000,0x01000000,0x01400000);
  assert(new_p1&&new_p1!=dead);select_process(new_p1,200+cycle);
  assert(K(read)(3,0x01201000,1)==-13&&K(provision)(dead,namespace_id,context_generation+1)==-3);
  namespace_id=300+cycle;context_generation=1;
  assert(K(provision)(new_p1,namespace_id,context_generation)==0); // Reclaims only fully dead owners.
  assert(K(retire_reaped_process)(dead)==-9&&K(retire_reaped_process)(new_p1)==-16);
  assert(K(openat)(-100,(uintptr_t)p1path,0,0)==3&&K(read)(3,0x01201000,4)==4&&K(close)(3)==0);
  assert(K(revoke_process)(new_p1)==0&&K(provision)(new_p1,namespace_id,1)==-116);
  context_generation=2;assert(K(provision)(new_p1,namespace_id,context_generation)==0);
  assert(K(openat)(-100,(uintptr_t)p1path,0,0)==3&&K(dispatch)(32,3,0,0,0)==4);
  // Leave both aliases open at exit; final reclamation must release the OFD.
  assert(K(read)(4,0x01201000,4)==4&&K(retire_reaped_process)(new_p1)==-16);
  assert(_O_runtime__common__posix_namespace_files__retire(new_p1,namespace_id,1)==-116);
  assert(K(read)(3,0x01201000,1)==1&&K(revoke_process)(dead)==-9);
  assert(P(exit_current)(0)==200+cycle&&K(retire_reaped_process)(new_p1)==-16);
  select_process(p0,101);
  assert(K(read)(sibling,(uintptr_t)dest,1)==1&&dest[0]==payload[7+cycle]);peer_valid();
 }
 assert(P(mark_reapable)(new_p1)==1&&P(begin_reap)(new_p1)==1);
 assert(A(destroy)(new_a1)==1&&M(drain_and_destroy_cspace)(new_c1)==1&&P(finalize_reap)(new_p1)==1);
 assert(K(retire_reaped_process)(new_p1)==0&&K(close)(sibling)==0);
 puts("64 real process generations reclaim dead contexts; live high-water, aliases and sibling bytes survive: PASS");
'''


@unittest.skipUnless(platform.system() == "Linux" and platform.machine() == "x86_64", "native Linux x86-64 carrier")
class PosixFileContextLifetimeTests(unittest.TestCase):
    def test_fully_reaped_owner_reclamation_preserves_live_authority(self):
        marker = ' printf("native file syscall component:'
        self.assertEqual(BASE.HARNESS.count(marker), 1)
        harness = BASE.HARNESS.replace(marker, LIFETIME + marker)
        # Reuse the real registry/image/codec producer, not its expected file
        # behavior. Every lifetime assertion above runs in the native carrier.
        with patch.object(BASE, "HARNESS", harness):
            BASE.PosixFileSyscallsTests.test_kernel_mediated_file_calls_use_real_registries_and_user_copy_checks(self)


if __name__ == "__main__":
    unittest.main()
