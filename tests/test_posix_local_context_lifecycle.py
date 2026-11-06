"""Existing real PCB/AS/CSpace lifetime contract through opt-in local files.

The only profile change is trusted native initialization. Reuse all original
registry, alias, dead-owner and survivor assertions; do not substitute a mock
process lifetime or silently reset a live generation high-water mark.
"""
import platform
import re
from unittest.mock import patch
import unittest

from tests import test_posix_file_context_lifecycle as LIFETIME


@unittest.skipUnless(platform.system()=='Linux' and platform.machine()=='x86_64','native Linux x86-64 carrier')
class LocalPosixContextLifetimeTests(unittest.TestCase):
    def test_64_reaped_generations_keep_local_authority_and_zero_codec(self):
        base=LIFETIME.BASE
        prefix,body=base.HARNESS.split('int main(void){',1)
        selected,count=re.subn(r'K\(init\)\((\d+)\)',r'K(init_backend)(\1,1)',body)
        self.assertGreater(count,0,'fixture failed to select actual trusted initialization')
        marker=' printf("native file syscall component:'
        self.assertEqual(selected.count(marker),1)
        selected=selected.replace(marker,LIFETIME.LIFETIME+'\n assert(C(encodes)()==0);\n'+marker)
        harness=prefix+'extern int64_t K(init_backend)(uint64_t,uint64_t);\nint main(void){'+selected
        with patch.object(base,'HARNESS',harness):
            base.PosixFileSyscallsTests.test_kernel_mediated_file_calls_use_real_registries_and_user_copy_checks(self)


if __name__=='__main__':unittest.main()
