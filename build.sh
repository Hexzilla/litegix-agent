#!/usr/bin/env bash

PACKAGE_NAME="litegix-agent"

GOOS="linux"
GOARCH="amd64"
BUILDMODE="release"
OUTPUT_NAME=$PACKAGE_NAME'-'$GOOS'-'$GOARCH

env GOOS=$GOOS GOARCH=$GOARCH go build -o $OUTPUT_NAME -ldflags "-s -w"
if [ $? -ne 0 ]; then
    echo 'An error has occurred! Aborting the script execution...'
    exit 1
fi