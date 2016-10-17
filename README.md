# skinfold
Use a Skinny (SCCP) phone on your network while connected to a corporate VPN


Skinfold uses the scappy python module to modify packets going through an Openconnect connection on the same machine.

Port forwarding and VPN access to CUCM mean you now have two way audio through a VPN connection
without having the IP phone on the machine where the Cisco VPN client is connected.

This has been tested and verifed on Debian Jessie with OpenConnect 6.

Openconnect must be installed and configured to the Anyconnect VPN. The default gateway on the phone must point to the server running the Openconnect instance. Routing must be active on the linux box.

Required

Openconnect
python
nfqueue-bindings-python
scapy-python



