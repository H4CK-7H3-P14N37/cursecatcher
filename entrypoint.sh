#!/bin/bash
# Dump the current environment to a file
printenv > /etc/environment
# Start cron in the foreground
cron -f