#!/usr/bin/env python
#  -*- coding: utf-8 -*-

"""
KerbMinder2.py

This script refreshes or renews kerberos tickets based on their status. It checks for
domain reachability and connectivity before proceeding. If machine is not bound to AD,
it will prompt the user for a login and store it in cache. For a renewal, the user is
prompted for their password and allowed only two tries. Two consecutive incorrect
passwords result in a warning dialog. If an incorrect attempt results in a locked
account, the user is informed their account is locked.

If the 'Remember password' box is checked, a correct password is saved to the keychain
and all subsequent renewals use it. Should the password get out of sync with the domain
password (e.g. after the user changes their password), the keychain will automatically
remove the old saved password and the user will be prompted to enter one.

This script is meant to be triggered by a launch agent working in conjunction with a
crankd launch daemon that looks for network state changes.

Last Revised - 01.10.2015
"""

from __future__ import print_function

import sys
import subprocess
import syslog
import os
import plistlib

import Pashua

__author__ = ( 'Peter Bukowinski (pmbuko@gmail.com), '
                'Francois Levaux-Tiffreau (fti@me.com)'
               )
__credits__ = ["Joe Chilcote",
               "Graham Gilbert",
               "Gary Larizza",
               "Per Olofsson",
               "Allister Banks",
               "Tim Sutton"]

__license__ = "GPL"
__version__ = "2.0"
__maintainer__ = "Peter Bukowinski"
__email__ = "pmbuko@gmail.com"
__status__ = "Development"

PATH_ROOT = os.path.dirname(os.path.realpath(__file__))
PATH_USER = os.path.expanduser('~/Library/Application Support/crankd')
PLIST_PATH = "/Library/Preferences/com.github.ftiff.KerbMinder2.plist"


def log_print(message, _log=True, _print=True):
    """Logs a message and prints it to stdout.
    Optionally disable either logging or stdout.
    """
    if _log:
        syslog.syslog(syslog.LOG_ALERT, message)
    if _print:
        print(message)


def domain_dig_check(domain):
    """Checks if AD domain is accessible by looking for SRV records for LDAP in DNS.
    Returns True if it can ping the domain, otherwise exits.
    """
    dig = subprocess.check_output(['dig', '-t', 'srv', '_ldap._tcp.' + domain])
    if 'ANSWER SECTION' not in dig:
        log_print('Domain not accessible. Exiting.')
        sys.exit(0)
    log_print('Domain is accessible.')
    return True


def login_dialog(image): # pragma: no cover
    """Displays login and password prompt using Pashua. Returns login as string."""

    message = 'Computer is not bound to AD. Enter your Kerberos credentials:'

    # Dialog config
    conf = '''
    # Window
    *.title = Kerberos Ticket Creation
    *.floating = 1

    # Image/logo
    img.type = image
    img.path = %s
    img.maxwidth = 128
    img.border = 0

    # Message
    msg.type = text
    msg.text = %s

    # Login field
    login.type = textfield
    login.label = Login:
    login.default = login
    login.width = 280
    login.mandatory = 1
    ''' % (image, message)

    try:
        realms = g_prefs.get_realms()
        conf += '''
            # Add a popup menu
            realm.type = popup
            realm.width = 285
            realm.label = Domain:
            '''
        for realm in realms:
            conf = conf + "realm.option = " + realm + "\n"
    except (KeyError, IOError):
        conf += '''
            realm.type = textfield
            realm.width = 280
            realm.label = Domain:
            '''

    conf += '''
    # Default button
    db.type = defaultbutton
    db.label = OK
    db.x = 0
    db.y = 0

    # Cancel button
    cb.type = cancelbutton
    cb.label = Cancel
    '''

    # Open dialog and get input
    dialog = Pashua.run(conf)

    # Check for Cancel before return
    if dialog['cb'] == '1':
        log_print('User canceled.')
        sys.exit(0)

    return dialog['login'] + '@' + dialog['realm'].upper()


def pass_dialog(kid, image, retry=False): # pragma: no cover
    """Displays password prompt using Pashua.
    Returns password as string and save checkbox state as 0 or 1.
    """

    message = 'Ticket for %s expired. Enter your password to renew:' % kid
    if retry:
        message = 'Your password was incorrect. Please try again:'

    # Dialog config
    conf = '''
    # Window
    *.title = Kerberos Ticket Renewal
    *.floating = 1

    # Image/logo
    img.type = image
    img.path = %s
    img.maxwidth = 64
    img.border = 0
    img.x = 0
    img.y = 100

    # Message
    msg.type = text
    msg.text = %s
    msg.x = 80
    msg.y = 110

    # Password field
    psw.type = password
    psw.mandatory = 1
    psw.width = 280
    psw.x = 82
    psw.y = 70

    # Save checkbox
    save.type = checkbox
    save.label = Remember this password in my keychain
    save.x = 80
    save.y = 45
    save.default = 1

    # Default button
    db.type = defaultbutton
    db.label = OK

    # Cancel button
    cb.type = cancelbutton
    cb.label = Cancel
    ''' % (image, message)

    # Open dialog and get input
    dialog = Pashua.run(conf)

    # Check for Cancel before return
    if dialog['cb'] == '1':
        log_print('User canceled.')
        sys.exit(0)

    return dialog['psw'], dialog['save']


def exit_dialog(message, title, log):
    """Display error to user, logs it and exit with error."""

    try:
        subprocess.check_output(['osascript', '-e',
                                 'display dialog "' + message + '" with title "' +
                                 title + '" with icon caution buttons {"OK"} default button 1'])

    except subprocess.CalledProcessError as error:
        log_print("Error displaying exit_dialog: " + str(error))

    else:
        log_print(log)

    finally:
        sys.exit(1)


class Principal(object):
    """login@REALM.TLD"""
    def __init__(self, principal=None):
        if principal is not None:
            self.principal = principal
        else:
            self.principal = ""

    def __str__(self):
        return self.principal

    class NotBound(Exception):
        pass


    def get(self):

        try:
            self.principal = self.get_from_ad()
        except (subprocess.CalledProcessError, Principal.NotBound):
            self.principal = self.get_from_user()

    @staticmethod
    def get_from_ad():
        """Returns the Kerberos ID of the current user by searching directory services. If no
        KID is found, either the search path is incorrect or the domain is not accessible."""

        try:
            output = subprocess.check_output(['dsconfigad', '-show'])
            if "Active Directory" in output:
                return Principal.get_principal_from_ad()
            else:
                raise Principal.NotBound("Computer is not bound.")

        except (subprocess.CalledProcessError, Principal.NotBound) as error:
            log_print(str(error))
            raise

    @staticmethod
    def get_principal_from_ad():
        """Returns the principal of the current user when computer is bound"""

        import re
        import getpass

        user_path = '/Users/' + getpass.getuser()

        try:
            output = subprocess.check_output(['dscl',
                                              '/Search',
                                              'read',
                                              user_path,
                                              'AuthenticationAuthority'],
                                             stderr=subprocess.STDOUT)
            match = re.search(r'[a-zA-Z0-9+_\-\.]+@[^;]+\.[A-Z]{2,}', output, re.IGNORECASE)
            match = match.group()

        except subprocess.CalledProcessError as error:
            log_print("Can't find Principal from AD: " + str(error))

        else:
            log_print('Kerberos Principal is ' + match)
            return match


    def get_from_user(self):
        """Will query cache. If unavailable, will query user, then write to cache."""
        try:
            principal = self.read()
            if principal:
                log_print("Found principal from cache: " + principal)
                return principal
        except(IOError, ValueError):
            log_print("Principal is not cached, asking user…")
            self.principal = login_dialog(g_prefs.get_image_path())

            try:
                self.write()
            except IOError as error:
                log_print("Cannot write principal: " + str(error))

        log_print("Principal is: " + str(self))
        return str(self)

    def exists(self):
        """Returns True if principal is defined"""
        if self.principal:
            return True
        else:
            return False

    def get_user_id(self):
        """Returns login"""
        return self.principal.split('@')[0]

    def get_realm(self):
        """Returns REALM.TLD"""
        return self.principal.split('@')[1]

    def write(self):
        """Writes Principal to cache"""
        path = g_prefs.get_principal_path()
        if not os.path.exists(os.path.dirname(path)):
            os.makedirs(os.path.dirname(path))

        try:
            with open(path, 'w') as _file:
                _file.write(self.principal)
        except IOError as error:
            log_print("Unexpected error: " + str(error))
            raise

    @staticmethod
    def read():
        """Returns principal from cache"""
        try:
            with open(g_prefs.get_principal_path(), 'r') as _file:
                principal = _file.read()
            if principal:
                return principal
            else:
                raise ValueError("Cannot read principal from cache")
        except (IOError, ValueError) as error:
            log_print("Warning: " + str(error))
            raise

    def delete(self):
        """Deletes cache file and removes from memory"""
        try:
            os.remove(g_prefs.get_principal_path())
        except OSError as error:
            log_print("Error deleting principal cache: " + str(error))
            raise

        self.principal = None


class Preferences(object):
    def __init__(self):
        pass

    @staticmethod
    def write(_plist_dict, _plist_path):
        try:
            plistlib.writePlist(_plist_dict, _plist_path)
        except (ValueError, TypeError, AttributeError) as error:
            log_print("Error writing Plist: " + str(error))
            raise

    @staticmethod
    def read(_plist_path):
        ret = ""
        try:
            ret = plistlib.readPlist(_plist_path)
        except (ValueError, TypeError, AttributeError) as error:
            log_print("Error reading Plist: " + str(error))
            raise
        else:
            return ret

    @staticmethod
    def get_realms():
        try:
            prefs = g_prefs.read(PLIST_PATH)
            return prefs["realms"]
        except (IOError, KeyError):
            log_print("Realms not specified.")
            raise

    @staticmethod
    def get_image_path():
        default_image_path = PATH_ROOT + '/KerbMinder_logo.png'
        try:
            prefs = g_prefs.read(PLIST_PATH)
            return prefs["image_path"]
        except (IOError, KeyError):
            return default_image_path

    @staticmethod
    def get_principal_path():
        default_principal_path = PATH_USER + '/kmfiles/principal'
        try:
            prefs = g_prefs.read(PLIST_PATH)
            return prefs["principal_path"]
        except (IOError, KeyError):
            return default_principal_path

    def set_image_path(self, image_path):
        raise NotImplementedError

    def write_defaults(self):
        raise NotImplementedError


class Keychain(object):
    def __init__(self):
        pass

    @staticmethod
    def exists(principal):
        """Checks keychain for kerberos entry."""

        user_id = principal.get_user_id()
        realm = principal.get_realm()

        try:
            subprocess.check_output(['security',
                                     'find-generic-password',
                                     '-a', user_id,
                                     '-l', realm + ' (' + user_id + ')',
                                     '-s', realm,
                                     '-c', 'aapl'],
                                    stderr=subprocess.STDOUT)
            log_print('Keychain entry found.')
            return True
        except subprocess.CalledProcessError:
            return False

    @staticmethod
    def store(principal, password):
        """Saves password to keychain for use by kinit.
        We don't use the flag -U (update) because it prompts the user to
        authorize the security process. Instead, it's safer to delete and store.
        """

        user_id = principal.get_user_id()
        realm = principal.get_realm()

        try:
            subprocess.check_output(['security',
                                     'add-generic-password',
                                     '-a', user_id,
                                     '-l', realm + ' (' + user_id + ')',
                                     '-s', realm,
                                     '-c', 'aapl',
                                     '-j', 'KerbMinder',
                                     '-T', '/usr/bin/kinit',
                                     '-w', str(password)])
            log_print('Added password to keychain.')
            return True

        except subprocess.CalledProcessError as error:
            log_print('Failed adding password to keychain: ' + str(error))
            return False

    @staticmethod
    def delete(principal):
        """Saves password to keychain for use by kinit."""

        user_id = principal.get_user_id()
        realm = principal.get_realm()

        try:
            subprocess.check_output(['security',
                                     'delete-generic-password',
                                     '-a', user_id,
                                     '-s', realm,
                                     '-c', 'aapl'],
                                    stderr=subprocess.STDOUT)
            log_print('Deleted Keychain entry.')
            return True

        except subprocess.CalledProcessError as error:
            log_print('Failed to delete keychain entry: ' + str(error))
            return False




class Ticket(object):

    class WrongPasswordError(Exception):
        """User has entered wrong password."""
        pass


    class PasswordExpiredError(Exception):
        """Password is expired."""
        pass


    class WrongUsernameError(Exception):
        """User has entered wrong username."""
        pass


    class RevokedError(Exception):
        """Too many unsuccessful passwords."""
        pass

    def __init__(self):


        self.kinit_return_exceptions = {
            "expired": Ticket.PasswordExpiredError,
            "incorrect": Ticket.WrongPasswordError,
            "revoked": Ticket.RevokedError,
            "unknown": Ticket.WrongUsernameError
        }

    def kinit_return_exception(self, _input):

        if _input in self.kinit_return_exceptions:
            raise self.kinit_return_exceptions[_input]
        else:
            return True

    @staticmethod
    def is_present():
        """
        Checks for kerberos ticket presence and either calls refresh or renew depending on
            ticket status.
        """
        try:
            subprocess.check_call(['klist', '--test'])

        except subprocess.CalledProcessError:
            log_print("Ticket is not present.")
            return False

        else:
            log_print("Ticket is present.")
            return True

    @staticmethod
    def refresh(_principal):
        log_print("Refreshing Ticket…")
        try:
            subprocess.check_output(['kinit', '--renew'])

        except subprocess.CalledProcessError:
            log_print("Can't refresh ticket.")
            raise

        else:
            log_print("Refreshed Ticket.")
            return True


    def kinit(self, principal, keychain, retry=False):
        """Calls kinit to initialize the Kerberos Ticket. Will use
        keychain if available, otherwise will ask user the password,
        optionally saving it to the keychain.
        """

        #(password, save) = ("", 0)

        try:
            if keychain.exists(principal):
                log_print('Initiating ticket with Keychain')

                out = subprocess.check_output(['kinit',
                                           '-l', '10h',
                                           '--renewable',
                                           str(principal)])
            else:
                log_print('Initiating ticket with password')
                (password, save) = pass_dialog(principal, g_prefs.get_image_path(), retry)
                _renew1 = subprocess.Popen(['echo', password], stdout=subprocess.PIPE)
                _renew2 = subprocess.Popen(['kinit',
                                            '-l', '10h',
                                            '--renewable',
                                            '--password-file=STDIN',
                                            str(principal)],
                                           stderr=subprocess.PIPE,
                                           stdin=_renew1.stdout,
                                           stdout=subprocess.PIPE)
                _renew1.stdout.close()
                out = _renew2.communicate()[1]

            self.kinit_return_exception(out)

        except (subprocess.CalledProcessError,
                Ticket.PasswordExpiredError,
                Ticket.WrongPasswordError,
                Ticket.RevokedError,
                Ticket.WrongUsernameError) as error:
            log_print("Error initiating ticket: " + str(error))
            raise

        else:
            if 'save' in locals():
                if save == "1":
                    keychain.store(principal, password)

            log_print("Ticket initiation OK")
            return True


def main():
    ticket = Ticket()
    principal = Principal()
    principal.get()
    keychain = Keychain()

    if not domain_dig_check(principal.get_realm()):
        sys.exit(0)

    if ticket.is_present():
        try:
            ticket.refresh(principal)
        except subprocess.CalledProcessError as error:
            log_print("Error: " + str(error))
        else:
            sys.exit(0)

    else:
        retry = False
        while True:
            try:
                ticket.kinit(principal, keychain, retry)

            except Ticket.WrongPasswordError:
                if not retry:
                    retry = True
                    log_print("Password mismatch")
                    continue
                else:
                    _message = "You entered a wrong password twice. Please make sure you are using the correct one."
                    _title = "Password Error"
                    _log = "Twice a password error. Exiting."
                    exit_dialog(_message, _title, _log)

            except Ticket.PasswordExpiredError:
                _message = "Your password has expired. Please change it and retry."
                _title = "Password expired"
                _log = "Password is expired. Exiting."
                exit_dialog(_message, _title, _log)

            except Ticket.RevokedError:
                _message = "Your domain account was locked out due to too many incorrect password attempts."
                _title = "Account Lockout"
                _log = "Ticket is revoked. Exiting."
                exit_dialog(_message, _title, _log)

            except Ticket.WrongUsernameError:
                log_print("Wrong Username")
                principal.delete()
                principal.get_from_user()
                continue

            else:
                break


g_prefs = Preferences()

if __name__ == '__main__':
    main()
