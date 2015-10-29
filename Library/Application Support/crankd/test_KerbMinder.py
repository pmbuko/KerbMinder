from subprocess import CalledProcessError
import nose
import logging
import os

from nose.tools import nottest
from KerbMinder2 import *
from unittest import TestCase
from mock import *

# set domain env -> export TEST_DOMAIN="DOMAIN.COM"
def no_credentials_found(*args, **kwargs):
    raise CalledProcessError(1, args, "klist: krb5_cc_get_principal: No credentials cache file found")


class TestPrincipal(TestCase):

    # TODO: ce machin doit marcher demain
    # def test_get_ok(self):
    #     principal = Principal()
    #     with patch('KerbMinder2.Principal.get_from_ad', return_value="testuser@TEST.COM") as get_from_ad:
    #         nose.tools.eq_(principal.get(), "testuser@TEST.COM")

    @patch('subprocess.check_output')
    def test_ad_notbound(self, mock_check_call):
        mock_check_call.returned_value = ""
        nose.tools.assert_raises(Principal.NotBound, Principal.get_from_ad)
        #mock_check_call.assert_called_with(['dsconfigad', '-show'])

    @patch('KerbMinder2.Principal.get_principal_from_ad')
    def test_ad_bound(self, mock_get_principal_from_ad):
        #https://github.com/nens/nensbuild/blob/master/nensbuild/tests.py
        with patch('subprocess.check_output', return_value = "Active Directory TEST") as check_output:
            Principal.get_from_ad()
        nose.tools.ok_(mock_get_principal_from_ad.called)
        check_output.assert_called_with(['dsconfigad', '-show'])

    @patch('getpass.getuser')
    def test_ad_bound_notenabled(self, mock_getpass_getuser):
        # https://github.com/nens/nensbuild/blob/master/nensbuild/tests.py
        # http://stackoverflow.com/questions/33214247/how-to-use-mock-any-with-assert-called-with
        mock_getpass_getuser.return_value = "testuser"

        _return_value = 'AuthenticationAuthority:  ;ShadowHash;HASHLIST:' \
                        '<SMB-NT,CRAM-MD5,RECOVERABLE,SALTED-SHA512-PBKDF2>  ' \
                        ';LocalCachedUser;/Active Directory/TEST/test.com:testuser' \
                        ':9A1F2D0C-B782-488A-80BA-CAC95AB6CAE9  ;Kerberosv5;;testuser@TEST.COM;' \
                        'TEST.COM; AuthenticationAuthority: ;Kerberosv5;;testuser@TEST.COM;TEST.COM; ' \
                        ';NetLogon;testuser;TEST'
        with patch('subprocess.check_output', return_value = _return_value) as check_output:
            nose.tools.eq_(Principal.get_principal_from_ad(), "testuser@TEST.COM")
            _, args, _ = check_output.mock_calls[0]

        nose.tools.eq_(args, (['dscl',
                      '/Search',
                      'read',
                      '/Users/testuser',
                      'AuthenticationAuthority'],))

class TestGlobal(TestCase):

    def test_domain_dig_check_notok(self):
        _return_value = """
; <<>> DiG 9.8.3-P1 <<>> -t srv _ldap._tcp.test.com
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 696
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 0

;; QUESTION SECTION:
;_ldap._tcp.test.com.	IN	SRV

;; AUTHORITY SECTION:
.			10800	IN	SOA	a.root-servers.net. nstld.verisign-grs.com. 2015101900 1800 900 604800 86400

;; Query time: 21 msec
;; SERVER: 10.0.0.2#53(10.0.0.2)
;; WHEN: Mon Oct 17 11:20:54 2015
"""
        with patch('subprocess.check_output', return_value = _return_value) as check_output:
            nose.tools.assert_raises(SystemExit, domain_dig_check, "TEST.COM")
        check_output.assert_called_with(['dig', '-t', 'srv', '_ldap._tcp.TEST.COM'])

    def test_domain_dig_check_ok(self):
        _return_value = """
;; Truncated, retrying in TCP mode.

; <<>> DiG 9.8.3-P1 <<>> -t srv _ldap._tcp.test.com
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 616
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 2, ADDITIONAL: 2

;; QUESTION SECTION:
;_ldap._tcp.test.com.	IN	SRV

;; ANSWER SECTION:
_ldap._tcp.test.com.	600 IN	SRV	0 100 389 ad.test.com.

;; AUTHORITY SECTION:
test.com.	1800	IN	NS	ns1.test.com.
test.com.	1800	IN	NS	ns2.test.com.

;; ADDITIONAL SECTION:
ns1.test.com. 1200	IN A	10.0.0.1
ns2.test.com. 1200	IN A	10.0.0.2

;; Query time: 1 msec
;; SERVER: 10.0.0.2#53(10.0.0.2)
;; WHEN: Mon Oct 17 11:20:54 2015
"""
        with patch('subprocess.check_output', return_value = _return_value) as check_output:
            nose.tools.ok_(domain_dig_check("TEST.COM"))
        check_output.assert_called_with(['dig', '-t', 'srv', '_ldap._tcp.TEST.COM'])

    def test_exit_dialog_ok(self):
        _message = _title = _log = "test"
        with patch('subprocess.check_output', return_value = True) as check_output:
            nose.tools.assert_raises(SystemExit, exit_dialog, _message, _title, _log)
        check_output.assert_called_with(['osascript', '-e',
                                 'display dialog "' + _message + '" with title "' +
                                 _title + '" with icon caution buttons {"OK"} default button 1'])

    @patch('KerbMinder2.log_print')
    def test_exit_dialog_fail(self, mock_log_print):
        _message = _title = _log = "test"
        with patch('subprocess.check_output', side_effect=subprocess.CalledProcessError(1, 'osascript', output="")) as check_output:
            nose.tools.assert_raises(SystemExit, exit_dialog, _message, _title, _log)
        mock_log_print.assert_called_with("Error displaying exit_dialog: Command 'osascript' returned non-zero exit status 1")
        check_output.assert_called_with(['osascript', '-e',
                                 'display dialog "' + _message + '" with title "' +
                                 _title + '" with icon caution buttons {"OK"} default button 1'])

class TestTicket(TestCase):

    @patch('subprocess.check_call')
    def test_ticket_false_ispresent(self, mock_check_call):
        mock_check_call.side_effect = no_credentials_found
        self.ticket = Ticket()
        returned = self.ticket.is_present()
        mock_check_call.assert_called_with(['klist', '--test'])
        nose.tools.assert_false(returned, "Ticket should NOT be present")

    @patch('subprocess.check_call')
    def test_ticket_true_ispresent(self, mock_check_call):
        mock_check_call.return_value = "Ticket is present."
        self.ticket = Ticket()
        returned = self.ticket.is_present()
        mock_check_call.assert_called_with(['klist', '--test'])
        nose.tools.ok_(returned, "Ticket should be present")

    #@patch('KerbMinder2.domain_dig_check')
    #mock_domain_dig_check.return_value = True


    @patch('subprocess.check_output')
    def test_ticket_refresh_false(self, mock_check_call):
        mock_check_call.side_effect = no_credentials_found
        self.principal = Principal("test@TEST.COM")
        self.ticket = Ticket()
        nose.tools.assert_raises(CalledProcessError, self.ticket.refresh, self.principal)
        mock_check_call.assert_called_with(['kinit', '--renew'])

    @patch('subprocess.check_output')
    def test_ticket_refresh_true(self, mock_check_call):
        mock_check_call.return_value = True
        self.principal = Principal("test@TEST.COM")
        self.ticket = Ticket()
        returned = self.ticket.refresh(self.principal)
        nose.tools.ok_(returned)
        mock_check_call.assert_called_with(['kinit', '--renew'])

    @nottest
    @patch('subprocess.check_call')
    def test_ticket_ispresent_true(self, mock_check_call):
        mock_check_call.return_value = "Ticket is present."
        self.ticket = Ticket()
        returned = self.ticket.is_present()
        mock_check_call.assert_called_with(['klist', '--test'])
        nose.tools.ok_(returned, "Ticket should be present")

    @patch('KerbMinder2.Keychain.exists')
    @patch('subprocess.check_output')
    def test_ticket_kinit_with_keychain_ok(self, mock_check_output, mock_keychain_exists):
        mock_keychain_exists.return_value = True
        mock_check_output.return_value = "OK"
        _principal = Principal()
        _keychain = Keychain()
        _ticket = Ticket()
        returned = _ticket.kinit(_principal, _keychain)
        nose.tools.ok_(returned, "NOT OK")

    @patch('KerbMinder2.Keychain.exists')
    @patch('subprocess.check_output')
    def ticket_kinit_with_keychain_custom(self, _error, _exception, mock_check_output, mock_keychain_exists):
        # http://paver.googlecode.com/svn@88/trunk/paver/tests/test_easy.py
        mock_keychain_exists.return_value = True
        mock_check_output.return_value = _error
        _principal = Principal()
        _keychain = Keychain()
        _ticket = Ticket()
        nose.tools.assert_raises(_exception, _ticket.kinit, _principal, _keychain)

    def test_kinit_with_keychain_custom(self):
        ask_error = [
            ("expired", Ticket.PasswordExpiredError),
            ("incorrect", Ticket.WrongPasswordError),
            ("revoked", Ticket.RevokedError),
            ("unknown", Ticket.WrongUsernameError)
        ]
        for (_error, _exception) in ask_error:
            self.ticket_kinit_with_keychain_custom(_error, _exception)

    def my_side_effect(*args, **kwargs):
        log_print(str(args[0]))

    @nottest
    @patch('KerbMinder2.Keychain.exists')
    @patch('subprocess.Popen')
    @patch('KerbMinder2.pass_dialog')
    def test_ticket_kinit_with_password_ok(self, mock_pass_dialog, mock_popen, mock_keychain_exists):
        mock_keychain_exists.return_value = False
        mock_popen.side_effect = self.my_side_effect
        mock_pass_dialog.return_value = ("1234", 0)
        _principal = Principal()
        _keychain = Keychain()
        _ticket = Ticket()
        returned = _ticket.kinit(_principal, _keychain)
        nose.tools.ok_(returned, "NOT OK")
        log_print(str(mock_popen.communicate.call_args()))
        #mock_popen.assert_called_with(['kinit', '-l', '10h', '--renewable', '--password-file=STDIN', ''])

@nottest
class TestDig(TestCase):
    def test_dig(self):
        try:
            domain = os.environ['TEST_DOMAIN']
        except KeyError:
            pass
        else:
            self.assertTrue(domain_dig_check(domain))

    def test_digfail(self):
        with self.assertRaises(SystemExit) as cm:
            domain_dig_check("EXAMPLE.COM")
        self.assertEqual(cm.exception.code, 0)

@nottest
class TestPrincipal2(TestCase):
    def test_principal(self):
        principal = Principal()
        principal.__str__ = MagicMock(return_value="test@TEST.COM")
        self.assertEqual(principal, "test@TEST.COM")

# @nottest
# class TestPrincipal(TestCase):
#     @patch.object(Principal, 'get_from_ad')
#     def test_create(self, mock_get_from_ad, mock_output):
#         #@patch('KerbMinder2.Principal', return_value='test@TEST.COM')
#         #pr = ""
#         #pr = patch('KerbMinder2.Principal.principal', "test@TEST.COM")
#         pr = Principal()
#         mock_get_from_ad.assert_called_with()
#         print mock_output
#     @patch('KerbMinder2.Principal.get_from_ad')
#     def test_get_ad(mock_get_from_ad):
#         mock_get_from_ad.return_value = "test@TEST.COM"
#         pr = Principal()
#         self.assertEqual(pr, "test@TEST.COM")
#
#



if __name__ == '__main__':
    nose.run()
