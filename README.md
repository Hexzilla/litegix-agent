# gophercon-jwt-repo
This is the complete code for my talk on Gophercon Europe 2020, [here](https://www.youtube.com/watch?v=myIJZMxpfTE&list=PLtoVuM73AmsKnUvoFizEmvWo0BbegkSIG&index=12)
Also a complete code for the article i wrote on Nexmo Developer Spotlight Program [here](https://www.nexmo.com/blog/2020/03/13/using-jwt-for-authentication-in-a-golang-application-dr)


go build
rm ./build-deb/litegix-agent_1.0-1_amd64/litegix/litegix-agent/litegix
mv ./litegix-agent ./build-deb/litegix-agent_1.0-1_amd64/litegix/litegix-agent/litegix
rm ./build-deb/litegix-agent_1.0-1_amd64.deb
cd build-deb
dpkg-deb --build --root-owner-group litegix-agent_1.0-1_amd64

scp ./litegix-agent_1.0-1_amd64.deb root@65.21.253.1:/root/
scp ./build-deb/litegix-agent_1.0-1_amd64.deb root@65.21.253.1:/root/


Password:
$Litegix2021!!!


scp ./litegix-agent root@65.21.253.1:/root/litegix
cp -f ./litegix /litegix/litegix-agent/litegix

sudo cp ./litegix-agent_1.0-1_amd64.deb /media/sf_shared/