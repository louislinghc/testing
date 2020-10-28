#!/bin/bash

echo "Copying marking script to student's VM"

scp check.sh student@192.168.0.9:/home/student 
