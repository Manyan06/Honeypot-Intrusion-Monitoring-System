#!/bin/bash
tail -f ~/cowrie/var/log/cowrie/cowrie.json | \
grep --line-buffered '"eventid": "cowrie.login"' | while read line
do
  echo "ALERT: SSH LOGIN ATTEMPT DETECTED"
done