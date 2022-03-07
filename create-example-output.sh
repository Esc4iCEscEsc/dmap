#! /usr/bin/env bash

set -ex

OUT_DIR=example-output/

if [ ! -f "$OUT_DIR/simple.xml" ]; then
	nmap -T5 -A -p 80,443 -oX - scanme.nmap.org > $OUT_DIR/simple.xml
fi

if [ ! -f "$OUT_DIR/all-reserved.xml" ]; then
	nmap -T5 -oX - scanme.nmap.org > $OUT_DIR/all-reserved.xml
fi

if [ ! -f "$OUT_DIR/syn-subnet.xml" ]; then
	echo "Next command requires root as we're doing a SYN scan + OS detection"
	sudo nmap -T5 -sS -O -oX - scanme.nmap.org > $OUT_DIR/syn-subnet.xml
fi

if [ ! -f "$OUT_DIR/random-ports.xml" ]; then
	nmap -T5 -iR 1000 -Pn -p 80 -oX - scanme.nmap.org > $OUT_DIR/random-ports.xml
fi

if [ ! -f "$OUT_DIR/service-detection.xml" ]; then
	nmap -T5 -sV -oX - scanme.nmap.org > $OUT_DIR/service-detection.xml
fi
