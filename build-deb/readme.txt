dpkg-deb --build --root-owner-group litegix-agent_1.0-1_amd64

sudo dpkg -i litegix-agent_1.0-1_amd64.deb 

systemctl status litegix-agent

systemctl start litegix-agent
