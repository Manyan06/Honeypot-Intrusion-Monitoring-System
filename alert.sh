#!/bin/bash

tail -n 0 -F /home/kali/cowrie/var/log/cowrie/cowrie.json | while read line
do
    # Successful login detection
    if echo "$line" | grep -q 'succeeded'; then
        echo "🚨 ALERT: Successful SSH Login Detected"
    fi

    # Command execution detection
    if echo "$line" | grep -q 'cowrie.command.input'; then
        cmd=$(echo "$line" | grep -oP '"input":"\K[^"]+')
        echo "⚡ Command Executed: $cmd"
    fi
done
