import nose

from KerbMinder import *
from unittest import TestCase
from mock import *

_dig_notok = """
; <<>> DiG 9.8.3-P1 <<>> -t srv _ldap._tcp.test.com
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 696
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 0

;; QUESTION SECTION:
;_ldap._tcp.test.com.   IN      SRV

;; AUTHORITY SECTION:
.                       10800   IN      SOA     a.root-servers.net. nstld.verisign-grs.com. 2015101900 1800 900 604800 86400

;; Query time: 21 msec
;; SERVER: 10.0.0.2#53(10.0.0.2)
;; WHEN: Mon Oct 17 11:20:54 2015
"""

_dscl_search_notreachable= """
AuthenticationAuthority: ;ShadowHash;HASHLIST:<SALTED-SHA512-PBKDF2> ;Kerberosv5;;testuser@LKDC:SHA1.8392019230AABB3399494BB1191999AAAF999AA;LKDC:SHA1.8392019230AABB3399494BB1191999AAAF999AA ;Kerberosv5Cert;;9170197410974109731097BBAA10101001029CC@LKDC:SHA1.9170197410974109731097BBAA10101001029CC;LKDC:SHA1.9170197410974109731097BBAA10101001029CC;
"""

_dscl_search_reachable = _dscl_search_notreachable +  """
AuthenticationAuthority: ;Kerberosv5;;testuser@TEST.COM;TEST.COM; ;NetLogon;testuser;TEST
No such key: AuthenticationAuthority
"""

class TestTest(TestCase):
    def test_dig_nottok(self):
        with patch('subprocess.check_output', return_value=_dig_notok) as mocked:
            nose.tools.assert_raises(SystemExit, main)

    def test_dig_stupid(self):
        with patch.object(Principal, 'get_from_ad', return_value="test@TEST.COM"):
            principal = Principal()
            principal.get()
            nose.tools.eq_(str(principal), "test@TEST.COM") 

    @patch('KerbMinder.Principal.cmd_dscl_search', Mock(return_value=_dscl_search_reachable))
    @patch('KerbMinder.Principal.cmd_dsconfigad_show', Mock(return_value="Active Directory"))
    def test_computer_bound_reachable(self):
        principal = Principal()
        principal.get()
        nose.tools.eq_(str(principal), "testuser@TEST.COM")

    @patch('KerbMinder.Principal.cmd_dscl_search', Mock(return_value=_dscl_search_notreachable))
    @patch('KerbMinder.Principal.cmd_dsconfigad_show', Mock(return_value="Active Directory"))
    def test_computer_bound_notreachable(self):
        principal = Principal()
        nose.tools.assert_raises(SystemExit, principal.get)
