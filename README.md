This is my attempt at making a vpn from scratch
It will definetly not be perfect but basic functionality should include:

-Secure Tunneling:
Creates encrypted tunnel between client and server using SSL/TLS
Uses TUN interface to capture and route network traffic
Supports multiple simultaneous client connections


-Network Configuration:
Automatically sets up IP addressing (10.0.0.0/24 network)
Configures routing tables on both client and server
Implements NAT for internet access through the VPN


-Production Features:
Proper cleanup of network configurations on shutdown
Error handling and graceful connection termination
Command-line interface for easy deployment
Thread management for multiple clients


-Limitations:
Linux-only support
Basic authentication (SSL certificates only)
No compression or traffic optimization
Assumes eth0 as main interface


To use:
1. First, you'll need to generate SSL certificates for testing:
   openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt -days 365 -nodes

2. Run the server(requires root/sudo):
   python p-chu.py --mode server --host 0.0.0.0 --port 5000

3. Run the client(requires root/sudo):
   python p-chu.py --mode client --host <server_ip> --port 5000

4. Test the connection on the client machine:
   ping 8.8.8.8  (Should work through VPN)
   curl ifconfig.me  (Should show server's IP)
