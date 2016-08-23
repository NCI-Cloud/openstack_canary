#!/bin/sh -e

dev="$1"
mpt='/mnt'
fs='ext4'
fil="${mpt}/testfile"
data="$2"

sudo mkfs -t "$fs" "$dev"
sudo mount "$dev" "$mpt"
sudo sh -c "echo '$data' > '$fil'"
sudo cat "$fil"
sudo rm -f "$fil"
sudo umount "$mpt"
