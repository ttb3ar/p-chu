import os
import fcntl
import struct
import socket
import ssl
import threading
import argparse
import subprocess
from typing import Tuple, Optional
import select

class TunInterface:
    """Handles the creation and management of a TUN network interface"""
    TUNSETIFF = 0x400454ca  # ioctl command for TUN interface
    IFF_TUN = 0x0001
    IFF_NO_PI = 0x1000

    def __init__(self, name: str = "tun0"):
        self.name = name
        self.tun_fd = None
        self.mtu = 1500

    def create(self) -> int:
        """Create and configure a TUN interface"""
        # Open TUN device file
        tun = open('/dev/net/tun', 'rb+')
        
        # Create struct for ioctl call
        ifr = struct.pack('16sH', self.name.encode(), self.IFF_TUN | self.IFF_NO_PI)
        
        # Create TUN interface
        fcntl.ioctl(tun, self.TUNSETIFF, ifr)
        self.tun_fd = tun.fileno()
        
        # Configure interface
        self._configure_interface()
        
        return self.tun_fd

    def _configure_interface(self):
        """Configure the TUN interface with IP address and bring it up"""
        commands = [
            f"ip addr add 10.0.0.1/24 dev {self.name}",
            f"ip link set dev {self.name} up",
            f"ip route add 10.0.0.0/24 dev {self.name}"
        ]
        
        for cmd in commands:
            try:
                subprocess.run(cmd.split(), check=True)
            except subprocess.CalledProcessError as e:
                print(f"Error configuring interface: {e}")
                raise

class EnhancedVPN:
    def __init__(self, host: str, port: int, is_server: bool = True):
        self.host = host
        self.port = port
        self.is_server = is_server
        self.buffer_size = 2048
        self.tun = TunInterface()
        self.running = False

    def create_ssl_context(self, is_server: bool) -> ssl.SSLContext:
        """Create SSL context for secure communication"""
        if is_server:
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.load_cert_chain(certfile='server.crt', keyfile='server.key')
        else:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        return context

    def handle_client(self, ssl_socket: ssl.SSLSocket, address: Tuple[str, int]):
        """Handle client connection and tunnel traffic"""
        print(f"New client connected: {address}")
        tun_fd = self.tun.create()

        try:
            while self.running:
                # Use select to monitor both TUN and socket
                readable, _, _ = select.select([tun_fd, ssl_socket], [], [], 1)

                for fd in readable:
                    if fd == tun_fd:
                        # Read from TUN and send to client
                        packet = os.read(tun_fd, self.buffer_size)
                        if packet:
                            # Add simple packet header (length)
                            length = len(packet)
                            header = struct.pack('!H', length)
                            ssl_socket.send(header + packet)

                    elif fd == ssl_socket:
                        # Read from client and write to TUN
                        header = ssl_socket.recv(2)
                        if not header:
                            break

                        length = struct.unpack('!H', header)[0]
                        packet = ssl_socket.recv(length)
                        if packet:
                            os.write(tun_fd, packet)

        except Exception as e:
            print(f"Error handling client {address}: {e}")
        finally:
            ssl_socket.close()

    def run_server(self):
        """Run VPN server"""
        context = self.create_ssl_context(True)
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        ssl_server = context.wrap_socket(server_socket, server_side=True)
        
        try:
            ssl_server.bind((self.host, self.port))
            ssl_server.listen(5)
            print(f"VPN Server listening on {self.host}:{self.port}")
            
            self.running = True
            while self.running:
                client_socket, address = ssl_server.accept()
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, address)
                )
                client_thread.start()

        except KeyboardInterrupt:
            print("Server shutting down...")
            self.running = False
        finally:
            ssl_server.close()

    def run_client(self):
        """Run VPN client"""
        context = self.create_ssl_context(False)
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssl_client = context.wrap_socket(client_socket)
        tun_fd = self.tun.create()

        try:
            ssl_client.connect((self.host, self.port))
            print(f"Connected to VPN server at {self.host}:{self.port}")
            
            self.running = True
            while self.running:
                readable, _, _ = select.select([tun_fd, ssl_client], [], [], 1)

                for fd in readable:
                    if fd == tun_fd:
                        # Read from TUN and send to server
                        packet = os.read(tun_fd, self.buffer_size)
                        if packet:
                            length = len(packet)
                            header = struct.pack('!H', length)
                            ssl_client.send(header + packet)

                    elif fd == ssl_client:
                        # Read from server and write to TUN
                        header = ssl_client.recv(2)
                        if not header:
                            break

                        length = struct.unpack('!H', header)[0]
                        packet = ssl_client.recv(length)
                        if packet:
                            os.write(tun_fd, packet)

        except KeyboardInterrupt:
            print("Client shutting down...")
            self.running = False
        except Exception as e:
            print(f"Error in client: {e}")
        finally:
            ssl_client.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Enhanced VPN Implementation")
    parser.add_argument('--host', default='localhost', help='Host address')
    parser.add_argument('--port', type=int, default=5000, help='Port number')
    parser.add_argument('--mode', choices=['server', 'client'], required=True,
                       help='Run as server or client')
    
    args = parser.parse_args()
    vpn = EnhancedVPN(args.host, args.port, args.mode == 'server')
    
    if args.mode == 'server':
        vpn.run_server()
    else:
        vpn.run_client()
