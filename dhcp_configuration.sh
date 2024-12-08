sudo ip addr add 172.16.0.1/12 dev enp0s8
sudo systemctl restart isc-dhcp-server
sudo systemctl status isc-dhcp-server
