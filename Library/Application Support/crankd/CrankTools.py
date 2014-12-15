#!/usr/bin/python2.7
#
#  CrankTools.py
#
#  The OnNetworkLoad method is called from crankd on a network state change, then a trigger
#  file is touched. The trigger file is watched by a launch agent that initiates a kerberos
#  ticket refresh.
#
#  Modified from Graham Gilbert's script
#  http://grahamgilbert.com/blog/2013/07/12/using-crankd-to-react-to-network-events/
#  which was modified from Gary Larizza's script (https://gist.github.com/glarizza/626169).
#
#  Last Revised - 12/15/2014

__author__ = 'Peter Bukowinski (pmbuko@gmail.com)'
__version__ = '1.0'

import os, pwd, re, sys, syslog, subprocess
from time import sleep

path_root = os.path.dirname(os.path.realpath(__file__))

syslog.openlog("KerbMinder")

class CrankTools():
  """The main CrankTools class needed for our crankd config plist"""

  def Trigger(self):
    """Touch a file that triggers the launch agent responsible for renewing the
    kerberos ticket, which must run in the user context."""
    if self.LinkState():
      path = path_root + '/kmfiles/trigger'
      basedir = os.path.dirname(path)
      if not os.path.exists(basedir):
        os.makedirs(basedir)
        os.chmod(basedir, 0o777)
      with open(path, 'a'):
        os.utime(path, None)
    else:
      message = 'No network access. Exiting.'
      syslog.syslog(syslog.LOG_ALERT, message)
      sys.exit(0)

  def getOrderedInterfaces(self):
    """Returns a list of network interfaces in proper service order."""
    rawInterfaces = subprocess.check_output(['networksetup', '-listnetworkserviceorder'])
    interfaces = re.findall(r' en[\d]+', rawInterfaces)
    if not interfaces:
      syslog.syslog(syslog.LOG_ALERT, 'No interfaces found. Exiting.')
      sys.exit(0)
    return [ i.lstrip(' ') for i in interfaces ]

  def LinkState(self):
    """Returns True if any ethernet interface has an ip address, otherwise False."""
    theState = False
    for interface in self.getOrderedInterfaces():
      if not subprocess.call(['ipconfig', 'getifaddr', interface]):
        theState = True
        message = interface + ' has an ip address.'
        syslog.syslog(syslog.LOG_ALERT, message)
        break

    return theState

  def OnNetworkLoad(self, *args, **kwargs):
    """Called from crankd directly on a Network State Change. We sleep for 30 seconds to ensure that
       an IP address has been cleared or attained, then trigger a kerberos ticket renewal.
    ---
    Arguments:
      *args and **kwargs - Catchall arguments coming from crankd
    Returns:  Nothing
    """
    duration = 30
    message = 'Network change detected. Waiting ' + str(duration) + 's for stability...'
    syslog.syslog(syslog.LOG_ALERT, message)
    sleep(duration)
    self.Trigger()

def main():
  """Instantiate the class"""
  crank = CrankTools()
  crank.OnNetworkLoad()

if __name__ == '__main__':
  main()
