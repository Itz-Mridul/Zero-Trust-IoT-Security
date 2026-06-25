#!/bin/bash

# Target to ping (Google DNS is reliable)
TARGET="8.8.8.8"

# Ping the target 3 times
/bin/ping -c 3 $TARGET > /dev/null 2>&1

# If the exit code ($?) is not 0, the internet is down
if [ $? -ne 0 ]; then
    echo "$(date): Internet down. Rebooting..." >> ~/watchdog.log
    sudo /sbin/reboot
fi
