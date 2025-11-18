import os
import fcntl
import struct
import socket
import ssl
import threading
import argparse
import subprocess
import select
from typing import Tuple, Optional, List

class VPNNetworkConfig:
    def __init__(self, tun_interface: str, vpn_network: str):
        self.tun_interface = tun_interface
        self.vpn_network = vpn_network
        self.original_forwarding = self._read_forwarding()

    def _read_forwarding(self) -> str:
        """Read current IPv4 forwarding setting"""
        try:
            with open('/proc/sys/net/ipv4/ip_forward', 'r') as f:
                return f.read().strip()
        except:
            return "0"

    def _run_command(self, cmd: str):
        """Run a single shell command"""
        try:
            subprocess.run(cmd, shell=True, check=True)
            print(f"Successfully executed: {cmd}")
        except subprocess.CalledProcessError as e:
            print(f"Error executing {cmd}: {e}")
            raise

    def setup_server_nat(self):
        """Configure NAT on the server"""
        commands = [
            "echo 1 > /proc/sys/net/ipv4/ip_forward",
            "iptables -F",
            "iptables -t nat -F",
            f"iptables -A FORWARD -i {self.tun_interface} -j ACCEPT",
            f"iptables -A FORWARD -o {self.tun_interface} -j ACCEPT",
            f"iptables -t nat -A POSTROUTING -s {self.vpn_network} -o eth0 -j MASQUERADE"
        ]
        
        for cmd in commands:
            self._run_command(cmd)
        print("Server NAT configuration completed")

    def setup_client_routing(self, server_ip: str):
        """Configure routing on the client - simplified for basic testing"""
        # For initial testing, just route VPN traffic through tunnel
        # Uncomment the default route line below for full VPN (will route all traffic)
        commands = [
            f"ip route add {self.vpn_network} dev {self.tun_interface}",
            # f"ip route add default via 10.0.0.1 dev {self.tun_interface} metric 100"
        ]
        
        for cmd in commands:
            self._run_command(cmd)
        print("Client routing configuration completed")
        print("Note: Only VPN subnet traffic is routed. Uncomment default route for full VPN.")

    def cleanup(self):
        """Cleanup NAT and routing configuration"""
        commands = [
            f"echo {self.original_forwarding} > /proc/sys/net/ipv4/ip_forward",
            "iptables -F",
            "iptables -t nat -F"
        ]
        
        for cmd in commands:
            try:
                self._run_command(cmd)
            except:
                pass  # Ignore errors during cleanup
        print("Network configuration cleaned up")

class TunInterface:
    """Handles the creation and management of a TUN network interface"""
    TUNSETIFF = 0x400454ca
    IFF_TUN = 0x0001
    IFF_NO_PI = 0x1000

    def __init__(self, name: str = "tun0", ip_address: str = "10.0.0.1/24"):
        self.name = name
        self.ip_address = ip_address
        self.tun = None  # Store the file object, not just the fd
        self.tun_fd = None
        self.mtu = 1500

    def create(self) -> int:
        """Create and configure a TUN interface"""
        self.tun = open('/dev/net/tun', 'r+b', buffering=0)
        ifr = struct.pack('16sH', self.name.encode(), self.IFF_TUN | self.IFF_NO_PI)
        fcntl.ioctl(self.tun, self.TUNSETIFF, ifr)
        self.tun_fd = self.tun.fileno()
        self._configure_interface()
        return self.tun_fd

    def _configure_interface(self):
        """Configure the TUN interface with IP address and bring it up"""
        commands = [
            f"ip addr add {self.ip_address} dev {self.name}",
            f"ip link set dev {self.name} up"
        ]
        
        for cmd in commands:
            try:
                subprocess.run(cmd, shell=True, check=True)
                print(f"Successfully executed: {cmd}")
            except subprocess.CalledProcessError as e:
                print(f"Error configuring interface: {e}")
                raise

    def close(self):
        """Close the TUN interface"""
        if self.tun:
            self.tun.close()

class EnhancedVPN:
    def __init__(self, host: str, port: int, is_server: bool = True, client_ip: str = "10.0.0.2"):
        self.host = host
        self.port = port
        self.is_server = is_server
        self.client_ip = client_ip
        self.buffer_size = 2048
        self.running = False
        self.network_config = VPNNetworkConfig("tun0", "10.0.0.0/24")
        
        # Different IPs for server and client
        if is_server:
            self.tun = TunInterface("tun0", "10.0.0.1/24")
        else:
            self.tun = TunInterface("tun0", "10.0.0.2/24")

    def create_ssl_context(self, is_server: bool) -> ssl.SSLContext:
        """Create SSL context for secure communication"""
        if is_server:
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            try:
                context.load_cert_chain(certfile='server.crt', keyfile='server.key')
            except FileNotFoundError:
                print("\nError: SSL certificates not found!")
                print("Generate them with:")
                print("openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes -subj '/CN=localhost'")
                raise
        else:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        return context

    def handle_client(self, ssl_socket: ssl.SSLSocket, address: Tuple[str, int]):
        """Handle client connection and tunnel traffic"""
        print(f"New client connected: {address}")
        tun_fd = self.tun.tun_fd

        try:
            while self.running:
                readable, _, _ = select.select([tun_fd, ssl_socket], [], [], 1)

                for fd in readable:
                    if fd == tun_fd:
                        packet = os.read(tun_fd, self.buffer_size)
                        if packet:
                            length = len(packet)
                            header = struct.pack('!H', length)
                            ssl_socket.sendall(header + packet)

                    elif fd == ssl_socket.fileno():
                        try:
                            header = ssl_socket.recv(2)
                            if not header or len(header) < 2:
                                print("Client disconnected")
                                break

                            length = struct.unpack('!H', header)[0]
                            packet = b''
                            while len(packet) < length:
                                chunk = ssl_socket.recv(length - len(packet))
                                if not chunk:
                                    break
                                packet += chunk
                            
                            if packet and len(packet) == length:
                                os.write(tun_fd, packet)
                        except ssl.SSLError as e:
                            print(f"SSL error: {e}")
                            break

        except Exception as e:
            print(f"Error handling client {address}: {e}")
        finally:
            ssl_socket.close()
            print(f"Client {address} disconnected")

    def run_server(self):
        """Run VPN server"""
        server_socket = None
        ssl_server = None
        try:
            print("Creating TUN interface...")
            self.tun.create()
            
            print("Setting up NAT...")
            self.network_config.setup_server_nat()
            
            print("Creating SSL context...")
            context = self.create_ssl_context(True)
            
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            ssl_server = context.wrap_socket(server_socket, server_side=True)
            
            ssl_server.bind((self.host, self.port))
            ssl_server.listen(5)
            print(f"\n✓ VPN Server listening on {self.host}:{self.port}")
            print(f"✓ TUN interface configured with IP 10.0.0.1/24")
            print("Waiting for clients...\n")
            
            self.running = True
            while self.running:
                try:
                    client_socket, address = ssl_server.accept()
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, address),
                        daemon=True
                    )
                    client_thread.start()
                except socket.timeout:
                    continue

        except KeyboardInterrupt:
            print("\n\nServer shutting down...")
            self.running = False
        except Exception as e:
            print(f"Server error: {e}")
            self.running = False
        finally:
            if ssl_server:
                ssl_server.close()
            self.tun.close()
            self.network_config.cleanup()
            print("Server stopped")

    def run_client(self):
        """Run VPN client"""
        ssl_client = None
        try:
            print("Creating TUN interface...")
            tun_fd = self.tun.create()
            
            print("Creating SSL connection...")
            context = self.create_ssl_context(False)
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ssl_client = context.wrap_socket(client_socket)
            
            print(f"Connecting to VPN server at {self.host}:{self.port}...")
            ssl_client.connect((self.host, self.port))
            
            print("Setting up routing...")
            self.network_config.setup_client_routing(self.host)
            
            print(f"\n✓ Connected to VPN server at {self.host}:{self.port}")
            print(f"✓ TUN interface configured with IP 10.0.0.2/24")
            print(f"✓ You can now ping 10.0.0.1 (server)\n")
            
            self.running = True
            while self.running:
                readable, _, _ = select.select([tun_fd, ssl_client], [], [], 1)

                for fd in readable:
                    if fd == tun_fd:
                        packet = os.read(tun_fd, self.buffer_size)
                        if packet:
                            length = len(packet)
                            header = struct.pack('!H', length)
                            ssl_client.sendall(header + packet)

                    elif fd == ssl_client.fileno():
                        try:
                            header = ssl_client.recv(2)
                            if not header or len(header) < 2:
                                print("Server disconnected")
                                break

                            length = struct.unpack('!H', header)[0]
                            packet = b''
                            while len(packet) < length:
                                chunk = ssl_client.recv(length - len(packet))
                                if not chunk:
                                    break
                                packet += chunk
                            
                            if packet and len(packet) == length:
                                os.write(tun_fd, packet)
                        except ssl.SSLError as e:
                            print(f"SSL error: {e}")
                            break

        except KeyboardInterrupt:
            print("\n\nClient shutting down...")
            self.running = False
        except Exception as e:
            print(f"Error in client: {e}")
            self.running = False
        finally:
            if ssl_client:
                ssl_client.close()
            self.tun.close()
            self.network_config.cleanup()
            print("Client stopped")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Enhanced VPN Implementation",
        epilog="""
Examples:
  # Generate SSL certificates (run once):
  openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes -subj '/CN=localhost'
  
  # Run server (needs root):
  sudo python3 vpn.py --mode server --host 0.0.0.0 --port 5000
  
  # Run client (needs root):
  sudo python3 vpn.py --mode client --host <server-ip> --port 5000
  
  # Test connection:
  ping 10.0.0.1  # from client to server
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('--host', default='0.0.0.0', help='Host address (default: 0.0.0.0 for server, must specify for client)')
    parser.add_argument('--port', type=int, default=5000, help='Port number (default: 5000)')
    parser.add_argument('--mode', choices=['server', 'client'], required=True,
                       help='Run as server or client')
    
    args = parser.parse_args()
    
    # Check if running as root
    if os.geteuid() != 0:
        print("Error: This program must be run as root (use sudo)")
        exit(1)
    
    vpn = EnhancedVPN(args.host, args.port, args.mode == 'server')
    
    if args.mode == 'server':
        vpn.run_server()
    else:
        vpn.run_client()
