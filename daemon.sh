#!/bin/bash
cd $(dirname ${0})
nohup python3 ./pusher.py > ./log.txt 2>&1 &