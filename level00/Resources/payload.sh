#!/bin/sh

# Works only in the usage of OverRide
# Don't forget to chmod +x this file before executing

echo 5276 > /tmp/payload

cat /tmp/payload - | /home/users/level00/level00
rm /tmp/payload
