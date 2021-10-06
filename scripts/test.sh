#!/bin/bash

osname=$(lsb_release -si)
echo $osname

#Define the string value
text=" 0.5 7.6"
IFS=' ' read -a strarr <<< "$text"

echo "This is cpu: ${strarr[0]}"
echo "This is mem: ${strarr[1]}"