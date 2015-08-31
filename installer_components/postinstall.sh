#!/bin/bash
#
# Thanks to Per Olofsson for the framework of this post-install
# source: https://github.com/MagerValp/Scripted-Mac-Package-Creation/blob/master/scripts/postinstall

# (Re)Load launch daemon and agent only if we're installing on a live system.
if [ "$3" == "/" ]; then
    # (re)load launch daemom
    launchctl unload /Library/LaunchDaemons/com.googlecode.pymacadmin.crankd.plist
    launchctl load /Library/LaunchDaemons/com.googlecode.pymacadmin.crankd.plist

    # (re)load launch agents for logged-in users
    for pid_uid in $(ps -axo pid,uid,args | grep -i "[l]oginwindow.app" | awk '{print $1 "," $2}'); do
        pid=$(echo $pid_uid | cut -d, -f1)
        uid=$(echo $pid_uid | cut -d, -f2)
        launchctl bsexec "$pid" chroot -u "$uid" / launchctl unload /Library/LaunchAgents/org.pmbuko.kerbminder.plist
        launchctl bsexec "$pid" chroot -u "$uid" / launchctl load /Library/LaunchAgents/org.pmbuko.kerbminder.plist
    done

fi

exit 0
