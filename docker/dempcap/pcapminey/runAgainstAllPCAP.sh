#!/bin/bash
FILES=./THREAT_PCAP/*
for f in $FILES
do
  echo "Processing $f file..."
  # take action on each file. $f store current file name
  python pcapfex.py $f
done
