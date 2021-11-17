#!/bin/bash

echo "Build project"
go build

echo "Clear old files"
rm ./build-deb/litegix-agent_1.0-1_amd64/litegix/litegix-agent/litegix
rm ./build-deb/litegix-agent_1.0-1_amd64.deb
mv ./litegix-agent ./build-deb/litegix-agent_1.0-1_amd64/litegix/litegix-agent/litegix

echo "Make deb package"
cd build-deb
dpkg-deb --build --root-owner-group litegix-agent_1.0-1_amd64

echo "Update release project"
cp ./litegix-agent_1.0-1_amd64.deb ~/gowork/litegix-agent-release/
cd ~/gowork/litegix-agent-release/
git commit -am "deploy"
git push origin main

