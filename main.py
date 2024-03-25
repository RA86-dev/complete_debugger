import psutil
import sysinfo
import platform,cpuinfo
import GPUtil
import time
import usb.core
import usb.util
import os
import socket
import ping3
import uuid
import re
from scapy.all import sniff, IP
import netifaces
import subprocess
import scapy.all as scapy
import psutil
import time
from scapy.all import *
import platform
import speedtest
import requests
from datetime import datetime
import pythonping
from colorama import Fore,Back,init,Style
init()
print(f"{Style.BRIGHT} COMPLETE DEBUGGER {Style.RESET_ALL}")
def get_device_name(ip_address):
    try:
        host_name = socket.gethostbyaddr(ip_address)
        return host_name[0]
    except socket.herror:
        return "Reverse DNS lookup failed"

def get_network_interfaces():
    interfaces = netifaces.interfaces()
    return interfaces

def get_interface_addresses(interface):
    addresses = netifaces.ifaddresses(interface)
    return addresses

def check_internet_speed():
    try:
        st = speedtest.Speedtest()
        download_speed = st.download() / 1024 / 1024  
        upload_speed = st.upload() / 1024 / 1024  
        return f"Download Speed: {download_speed:.2f} Mbps, Upload Speed: {upload_speed:.2f} Mbps"
    except Exception as c:
        return f"error! {c} Most errors are caused by the 403 FORBIDDEN. to fix this, just run other programs."
def check_public_ip():
    try:
        response = requests.get("https://api.ipify.org")
        public_ip = response.text
        return f"Public IP Address: {public_ip}"
    except Exception as e:
        return f"Error retrieving public IP address: {e}"

def check_network_latency(host="www.google.com"):
    try:
        latency = pythonping.ping(host, count=5).rtt_avg_ms
        return f"Network Latency to {host}: {latency} ms"
    except Exception as e:
        return f"Error checking network latency: {e}"

def get_interface_info():
    interfaces = netifaces.interfaces()
    info = {}
    for interface in interfaces:
        addrs = netifaces.ifaddresses(interface)
        info[interface] = addrs
    return info

def detect_proxy():
    proxy_settings = os.environ.get("http_proxy") or os.environ.get("HTTP_PROXY")
    if proxy_settings:
        return f"Proxy Server configured: {proxy_settings}"
    else:
        return "No Proxy Server configured"


    return connected_devices

def capture_traffic(interface):
    """
    Capture network traffic on a given interface.
    """
    try:
        import pyshark

        capture = pyshark.LiveCapture(interface=interface)
        for packet in capture.sniff_continuously(packet_count=1):
            print(packet)
    except ImportError:
        print(
            "PyShark library not found. Please install it to use traffic capture functionality."
        )
    except Exception as e:
        print(f"Failed to capture traffic on interface {interface} - {e}")

def check_network(host="www.google.com", timeout=2):
    try:
        ip = socket.gethostbyname(host)
        ping = ping3.ping(ip, timeout=timeout)
        if ping is not None:
            return f"Network: {host} is reachable. Round trip time: {ping} ms"
        else:
            return 404
    except Exception as e:
        return f"Cannot connect. Error: {e}"

def get_mac_address(interface=None):
    if interface:
        try:
            mac = netifaces.ifaddresses(interface)[netifaces.AF_LINK][0]["addr"]
            return mac
        except Exception as e:
            return f"Cannot get MAC address. Error: {e}"
    else:
        mac = ":".join(
            [
                "{:02x}".format((uuid.getnode() >> elements) & 0xFF)
                for elements in range(0, 2 * 6, 2)
            ][::-1]
        )
        return mac


def print_network_connections():
    connections = psutil.net_connections()
    
    mx = str("Current Network Connections:<br>")
    lenX = len(connections)
    for conn in connections:
        mx += str(
            f"PID: {conn.pid}, Status: {conn.status}, Local Address: {conn.laddr}, Remote Address: {conn.raddr}<br>"
        )
    return mx


def check_firewall_status():
    system = platform.system()
    
    if system == "Windows":
        try:
            result = subprocess.run(['netsh', 'advfirewall', 'show', 'allprofiles', 'state'], capture_output=True, text=True, check=True)

            if 'ON' in result.stdout:
                print("Firewall is enabled on Windows.")
            else:
                print("Firewall is disabled on Windows.")

        except subprocess.CalledProcessError as e:
            print("Error occurred:", e)

    elif system == "Darwin":
        try:
            result = subprocess.run(['/usr/libexec/ApplicationFirewall/socketfilterfw', '--getglobalstate'], capture_output=True, text=True, check=True)

            if 'Enabled' in result.stdout:
                return "Firewall is enabled on macOS."
            else:
                return "Firewall is disabled on macOS."

        except subprocess.CalledProcessError as e:
            return "Error occurred:", e

    elif system == "Linux":
        try:
            result = subprocess.run(['sudo', 'ufw', 'status'], capture_output=True, text=True, check=True)

            if 'Status: active' in result.stdout:
                return "Firewall is enabled on Linux."
            else:
                return "Firewall is disabled on Linux."

        except subprocess.CalledProcessError as e:
            return "Error occurred:", e

    else:
        return "Unsupported operating system."

def get_entry_points():
    gateways = netifaces.gateways()
    return gateways

def check_dns_cache():
    if platform.system() == "Windows":
        try:
            output = subprocess.check_output(["ipconfig", "/displaydns"]).decode(
                "utf-8"
            )
            return output
        except Exception as e:
            return f"Error checking DNS cache: {e}"
    elif platform.system() == "Linux":
        try:
            output = subprocess.check_output(
                ["sudo", "rndc", "dumpdb", "-cache"]
            ).decode("utf-8")
            return output
        except Exception as e:
            return f"Error checking DNS cache: {e}"
    elif platform.system() == "Darwin":
        try:
            output = subprocess.check_output(
                ["sudo", "dscacheutil", "-cachedump"]
            ).decode("utf-8")
            return output
        except Exception as e:
            return f"Error checking DNS cache: {e}"
    else:
        return "Unsupported platform"

def is_run_with_sudo():
    return "SUDO_USER" in os.environ

def check_dns_servers():
    if platform.system() == "Windows":
        try:
            output = subprocess.check_output(["ipconfig", "/all"]).decode("utf-8")
            dns_servers = re.findall(
                r"DNS Servers[.:] ((?:\d{1,3}\.){3}\d{1,3})", output
            )
            return dns_servers
        except Exception as e:
            return f"Error checking DNS servers: {e}"
    elif platform.system() in ["Linux", "Darwin"]:
        try:
            output = subprocess.check_output(["cat", "/etc/resolv.conf"]).decode(
                "utf-8"
            )
            dns_servers = re.findall(r"nameserver ((?:\d{1,3}\.){3}\d{1,3})", output)
            return dns_servers
        except Exception as e:
            return f"Error checking DNS servers: {e}"
    else:
        return "Unsupported platform"

def dns_lookup(domain):
    try:
        ip_address = socket.gethostbyname(domain)
        return f"DNS Lookup for {domain}: {ip_address}"
    except Exception as e:
        return f"Error performing DNS lookup: {e}"

def ip_geolocation(ip_address):
    try:
        response = requests.get(f"https://ipinfo.io/{ip_address}/json")
        data = response.json()
        return f"Geolocation for IP Address {ip_address}: {data.get('city')}, {data.get('region')}, {data.get('country')}"
    except Exception as e:
        return f"Error retrieving IP geolocation: {e}"

def get_routing_table():
    try:
        output = subprocess.check_output(["netstat", "-rn"]).decode("utf-8")
        return output
    except Exception as e:
        return f"Error retrieving routing table: {e}"
import psutil

def check_active_network_interfaces():
    try:
        interfaces = psutil.net_if_addrs()
        active_interfaces = [interface for interface in interfaces if interfaces[interface]]
        
        formatted_output = "Active network interfaces:\n"
        for interface in active_interfaces:
            formatted_output += f"{interface}\n"
        
        return formatted_output
    except Exception as e:
        return f"Error checking active network interfaces: {e}"

# Example usage:



def check_active_tcp_connections():
    tcp_connections = psutil.net_connections(kind="tcp")
    return tcp_connections

def check_active_udp_connections():
    udp_connections = psutil.net_connections(kind="udp")
    return udp_connections

def check_network_traffic_by_protocol(protocol):
    try:
        command = f"tcpdump -i any {protocol}"
        result = subprocess.run(command.split(), capture_output=True, text=True)
        return result.stdout
    except Exception as e:
        return f"Error capturing network traffic for protocol {protocol}: {e}"

def check_network_interface_statistics():
    stats = psutil.net_io_counters(pernic=True)
    return stats

def check_listening_ports():
    listening_ports = psutil.net_connections(kind="inet")
    listening_ports = [conn for conn in listening_ports if conn.status == "LISTEN"]
    return listening_ports

def check_established_connections():
    established_connections = psutil.net_connections(kind="inet")
    established_connections = [
        conn for conn in established_connections if conn.status == "ESTABLISHED"
    ]
    return established_connections

def check_network_bandwidth_usage():
    bandwidth_usage = psutil.net_io_counters()
    return bandwidth_usage

def check_network_packet_loss():
    try:
        command = "ping -c 10 www.google.com"
        result = subprocess.run(command.split(), capture_output=True, text=True)
        packet_loss = result.stdout.splitlines()[-2].split(",")[2].strip().split()[0]
        return f"Packet Loss: {packet_loss}"
    except Exception as e:
        return f"Error checking network packet loss: {e}"

def capture_and_analyze_packets():
    x = ""
    def packet_callback(packet):

    # Check for specific conditions or errors in the packet
        if packet.haslayer('IP'):
            ip_src = packet['IP'].src
            ip_dst = packet['IP'].dst
            
            # Example error conditions
            if 'ICMP' in packet:
                dv_src = get_device_name(ip_src)
                dv_dst = get_device_name(ip_dst)
                x += f"ICMP packet from {ip_src} (Device Name: {dv_src}) to {ip_dst}(Device Name: {dv_dst}) detected <br>"
            if packet['IP'].proto == 6:  # TCP
                dv_src = get_device_name(ip_src)
                dv_dst = get_device_name(ip_dst)
                x += f"TCP packet from {ip_src} to {ip_dst} detected <br>"
            if 'Raw' not in packet:
                dv_src = get_device_name(ip_src)
                dv_dst = get_device_name(ip_dst)
                x += f"No raw data received from {ip_src} (Device Name: {dv_src}) to {ip_dst} (Device Name: {dv_dst}) <br>"
            print(packet.summary())

        ip_layer = packet.getlayer(IP)
        if ip_layer:
            x += "Source IP:", ip_layer.src,"<br>"
            x += "Destination IP:", ip_layer.dst,"<br>"
            x += "Protocol:", ip_layer.proto,"<br>"
            x += "","<br>"


    print("Sniffing started...")
    sniff(prn=packet_callback, filter="tcp", count=2)  
    print('Sniff Ended!')
    return x

def check_dns_resolution_time(domain):
    try:
        resolver = socket.getaddrinfo
        start_time = time.time()
        resolver(domain, 80)
        end_time = time.time()
        resolution_time = end_time - start_time
        return f"DNS Resolution Time for {domain}: {resolution_time} seconds"
    except Exception as e:
        return f"Error checking DNS resolution time: {e}"

def check_arp_cache():
    try:
        command = "arp -a"
        result = subprocess.run(command.split(), capture_output=True, text=True)
        return result.stdout
    except Exception as e:
        return f"Error checking ARP cache: {e}"
def check_network_buffer_sizes():
    try:
        # Retrieve network buffer sizes
        buffer_sizes = psutil.net_io_counters(pernic=True)

        # Format network buffer sizes
        formatted_buffer_sizes = "Network buffer sizes:\n"
        for interface, stats in buffer_sizes.items():
            formatted_buffer_sizes += f"Interface: {interface}\n"
            formatted_buffer_sizes += f"\tBytes Sent: {stats.bytes_sent}\n"
            formatted_buffer_sizes += f"\tBytes Received: {stats.bytes_recv}\n\n"

        return formatted_buffer_sizes
    except Exception as e:
        return f"Error checking network buffer sizes: {e}"

def check_network_interface_speed():
    try:
        # Retrieve network interface speeds
        interface_speeds = psutil.net_if_stats()

        # Format network interface speeds
        formatted_speeds = "Network interface speeds:\n"
        for interface, stats in interface_speeds.items():
            formatted_speeds += f"Interface: {interface}\n"
            formatted_speeds += f"\tSpeed: {stats.speed} Mbps\n\n"

        return formatted_speeds
    except Exception as e:
        return f"Error checking network interface speeds: {e}"




def check_network_mtu():
    try:
        # Execute ifconfig command
        ifconfig_output = subprocess.check_output(['ifconfig']).decode('utf-8')

        # Split the output by interface blocks
        interface_blocks = ifconfig_output.split('\n\n')

        # Retrieve network interface MTU values
        formatted_mtu = "Network interface MTU:\n"
        for interface_block in interface_blocks:
            lines = interface_block.split('\n')
            if len(lines) > 0:
                interface_name = lines[0].split(':')[0]
                mtu_line = [line for line in lines if 'MTU:' in line]
                if mtu_line:
                    mtu_value = mtu_line[0].split('MTU:')[1].split()[0]
                    formatted_mtu += f"Interface: {interface_name}\n"
                    formatted_mtu += f"\tMTU: {mtu_value}\n\n"

        return formatted_mtu
    except Exception as e:
        return f"Error checking network interface MTU: {e}"

def check_network_interface_status():
    try:
        # Retrieve network interface status
        interface_status = psutil.net_if_stats()

        # Format network interface status
        formatted_status = "Network interface status:\n"
        for interface, stats in interface_status.items():
            formatted_status += f"Interface: {interface}\n"
            formatted_status += f"\tIs Up: {stats.isup}\n"
            formatted_status += f"\tIs Running: {stats.isrunning}\n"
            formatted_status += f"\tIs Loopback: {stats.isloopback}\n"
            formatted_status += f"\tMTU: {stats.mtu}\n\n"

        return formatted_status
    except Exception as e:
        return f"Error checking network interface status: {e}"


def check_network_interface_configuration():
    try:
        # Check active network interfaces
        interfaces = psutil.net_if_addrs()
        active_interfaces = [interface for interface, stats in interfaces.items() if any(stats)]

        # Format active network interfaces
        formatted_interfaces = "Active network interfaces:\n"
        for interface in active_interfaces:
            formatted_interfaces += f"Interface: {interface}\n"
            for addr in interfaces[interface]:
                formatted_interfaces += f"\tAddress: {addr.address}\n"
                formatted_interfaces += f"\tNetmask: {addr.netmask}\n"
                formatted_interfaces += f"\tBroadcast: {addr.broadcast}\n"

        # Check active network services
        services = psutil.net_connections()
        active_services = [service for service in services if service.status == 'LISTEN']

        # Format active network services
        formatted_services = "Active network services:\n"
        for service in active_services:
            formatted_services += f"Local Address: {service.laddr}\n"
            formatted_services += f"Remote Address: {service.raddr}\n"
            formatted_services += f"Status: {service.status}\n\n"

        return f"{formatted_interfaces}\n{formatted_services}"
    except Exception as e:
        return f"Error checking active network info: {e}"

def check_active_network_services():
    active_services = psutil.net_connections()
    return active_services

def check_network_broadcast_traffic():
    try:
        command = "tcpdump -i any -n -e -c 10 broadcast"
        result = subprocess.run(command.split(), capture_output=True, text=True)
        if result.returncode != 0:
            return f"Error capturing network broadcast traffic: {result.stderr}"
        
        output = result.stdout
        connections = re.findall(r'sconn\(.+?\)', output)
        
        formatted_output = "Network broadcast traffic:\n"
        for conn in connections:
            formatted_output += f"{conn}\n"
        
        return formatted_output
    except Exception as e:
        return f"Error capturing network broadcast traffic: {e}"

def get_interface_details():
    interfaces = netifaces.interfaces()
    details = {}
    for interface in interfaces:
        addresses = netifaces.ifaddresses(interface)
        ipv4_address = None
        mac_address = None
        netmask = None
        if netifaces.AF_INET in addresses:
            ipv4_address = addresses[netifaces.AF_INET][0]["addr"]
            netmask = addresses[netifaces.AF_INET][0]["netmask"]
        if netifaces.AF_LINK in addresses:
            mac_address = addresses[netifaces.AF_LINK][0]["addr"]
        details[interface] = {
            "ip_address": ipv4_address,
            "mac_address": mac_address,
            "netmask": netmask,
        }
    return details

def check_active_tcp_connections():
    tcp_connections = psutil.net_connections(kind="tcp")
    return tcp_connections

def check_active_udp_connections():
    udp_connections = psutil.net_connections(kind="udp")
    return udp_connections

def check_network_traffic_by_protocol(protocol):
    try:
        command = f"tcpdump -i any {protocol}"
        result = subprocess.run(command.split(), capture_output=True, text=True)
        return result.stdout
    except Exception as e:
        return f"Error capturing network traffic for protocol {protocol}: {e}"

def check_network_interface_statistics():
    stats = psutil.net_io_counters(pernic=True)
    return stats

def check_listening_ports():
    listening_ports = psutil.net_connections(kind="inet")
    listening_ports = [conn for conn in listening_ports if conn.status == "LISTEN"]
    return listening_ports
def check_network_interface_mtu(interface):
    try:
        mtu = netifaces.ifaddresses(interface).get(netifaces.AF_INET)[0]['mtu']
        return f"MTU of interface {interface}: {mtu}"
    except Exception as e:
        return f"Error retrieving MTU for interface {interface}: {e}"

def check_established_connections():
    established_connections = psutil.net_connections(kind="inet")
    established_connections = [
        conn for conn in established_connections if conn.status == "ESTABLISHED"
    ]
    return established_connections

def check_network_bandwidth_usage():
    try:
        # Retrieve network bandwidth usage
        bandwidth_usage = psutil.net_io_counters()

        # Format network bandwidth usage
        formatted_bandwidth_usage = "Network bandwidth usage:\n"
        formatted_bandwidth_usage += f"Bytes Sent: {bandwidth_usage.bytes_sent}\n"
        formatted_bandwidth_usage += f"Bytes Received: {bandwidth_usage.bytes_recv}\n"
        formatted_bandwidth_usage += f"Packets Sent: {bandwidth_usage.packets_sent}\n"
        formatted_bandwidth_usage += f"Packets Received: {bandwidth_usage.packets_recv}\n"
        formatted_bandwidth_usage += f"Errors in Sent: {bandwidth_usage.errout}\n"
        formatted_bandwidth_usage += f"Errors in Received: {bandwidth_usage.errin}\n"

        return formatted_bandwidth_usage
    except Exception as e:
        return f"Error checking network bandwidth usage: {e}"

def check_network_packet_loss():
    try:
        command = "ping -c 10 www.google.com"
        result = subprocess.run(command.split(), capture_output=True, text=True)
        packet_loss = result.stdout.splitlines()[-2].split(",")[2].strip().split()[0]
        return f"Packet Loss: {packet_loss}"
    except Exception as e:
        return f"Error checking network packet loss: {e}"

def check_dns_resolution_time(domain):
    try:
        resolver = socket.getaddrinfo
        start_time = time.time()
        resolver(domain, 80)
        end_time = time.time()
        resolution_time = end_time - start_time
        return f"DNS Resolution Time for {domain}: {resolution_time} seconds"
    except Exception as e:
        return f"Error checking DNS resolution time: {e}"

def check_arp_cache():
    try:
        command = "arp -a"
        result = subprocess.run(command.split(), capture_output=True, text=True)
        return result.stdout
    except Exception as e:
        return f"Error checking ARP cache: {e}"

def check_network_buffer_sizes():
    buffer_sizes = psutil.net_io_counters(pernic=True)
    return buffer_sizes

def check_network_interface_speed():
    interface_speeds = psutil.net_if_stats()
    return interface_speeds

def check_network_mtu():
    mtu = psutil.net_if_stats()
    return mtu

def check_network_interface_status():
    interface_status = psutil.net_if_stats()
    return interface_status

def check_network_interface_errors():
    try:
        # Retrieve network interface statistics
        interface_errors = psutil.net_if_stats()

        # Format network interface errors
        formatted_errors = "Network interface errors:\n"
        for interface, stats in interface_errors.items():
            formatted_errors += f"Interface: {interface}\n"
            formatted_errors += f"\tBytes Sent: {stats.bytes_sent}\n"
            formatted_errors += f"\tBytes Received: {stats.bytes_recv}\n"
            formatted_errors += f"\tPackets Sent: {stats.packets_sent}\n"
            formatted_errors += f"\tPackets Received: {stats.packets_recv}\n"
            formatted_errors += f"\tErrors in Sent: {stats.errout}\n"
            formatted_errors += f"\tErrors in Received: {stats.errin}\n\n"

        return formatted_errors
    except Exception as e:
        return f"Error checking network interface errors: {e}"
def check_firewall_rules():
    try:
        if platform.system() == 'Linux':
            output = subprocess.check_output(['iptables', '-L']).decode('utf-8')
        elif platform.system() == 'Windows':
            output = subprocess.check_output(['netsh', 'advfirewall', 'firewall', 'show', 'rule', 'name=all']).decode('utf-8')
        elif platform.system() == 'Darwin':
            output = subprocess.check_output(['pfctl', '-sr']).decode('utf-8')
        else:
            return "Unsupported platform"
        return output
    except Exception as e:
        return f"Error retrieving firewall rules: {e}"
def check_active_tcp_connections():
    tcp_connections = psutil.net_connections(kind='tcp')
    return tcp_connections
def arp(interface=None):
    try:
        arp_cmd = ['arp', '-a']
        if interface:
            arp_cmd.extend(['-i', interface])
        
        arp_output = subprocess.check_output(arp_cmd).decode('utf-8')
        arp_lines = arp_output.splitlines()
        arp_table = []

        for line in arp_lines[1:]:
            parts = line.split()
            if len(parts) >= 2:
                arp_table.append({'IP Address': parts[0], 'MAC Address': parts[1]})
        
        return arp_table

    except subprocess.CalledProcessError as e:
        print("Error executing arp command:", e)
        return None

def get_dns_info(host):

    try:
        ip_address = socket.gethostbyname(host)
        hostname, aliaslist, ipaddrlist = socket.gethostbyaddr(ip_address)
        return {'ip_address': ip_address, 'hostname': hostname, 'aliases': aliaslist};
    except Exception as e:
        return f"Error getting DNS information for host {host}: {e}";

def check_active_network_services():
    active_services = psutil.net_connections()
    return active_services

def check_network_broadcast_traffic():
    try:
        command = "tcpdump -i any -n -e -c 10 broadcast"
        result = subprocess.run(command.split(), capture_output=True, text=True)
        return result.stdout
    except Exception as e:
        return f"Error capturing network broadcast traffic: {e}"

def check_network_multicast_traffic():
    try:
        command = "tcpdump -i any -n -e -c 10 multicast"
        result = subprocess.run(command.split(), capture_output=True, text=True)
        return result.stdout
    except Exception as e:
        return f"Error capturing network multicast traffic: {e}"
def get_usb_devices_info():
    """
    Retrieve information about USB devices plugged into the system.
    Returns a list of dictionaries, where each dictionary contains information about a USB device.
    """
    usb_devices_info = []

    # Find all USB devices
    devices = usb.core.find(find_all=True)

    for device in devices:
        usb_device_info = {}
        usb_device_info['Device ID'] = f"{device.idVendor:04x}:{device.idProduct:04x}"
        usb_device_info['Device Class'] = get_class_name(device.bDeviceClass)
        if device.bDeviceClass == 0x00:
            usb_device_info['Device Class'] += "  NOTE: A Device is connected to your computer."
        usb_device_info['Device Subclass'] = device.bDeviceSubClass
        usb_device_info['Device Protocol'] = device.bDeviceProtocol

        # Get configuration descriptor
        config = device.get_active_configuration()

        # Iterate over each interface
        for interface in config:
            usb_device_info['Interface Number'] = interface.bInterfaceNumber
            usb_device_info['Interface Class'] = get_class_name(interface.bInterfaceClass)
            usb_device_info['Interface Subclass'] = interface.bInterfaceSubClass
            usb_device_info['Interface Protocol'] = interface.bInterfaceProtocol

            # Iterate over each endpoint
            for endpoint in interface:
                usb_device_info['Endpoint Address'] = endpoint.bEndpointAddress
                usb_device_info['Endpoint Type'] = endpoint.bmAttributes
                usb_device_info['Packet Size'] = endpoint.wMaxPacketSize

        usb_devices_info.append(usb_device_info)
    
    return usb_devices_info

def get_class_name(class_code):
    class_names = {
        0x00: "Device",
        0x01: "Audio",
        0x02: "Communications and CDC Control",
        0x03: "Human Interface Device (HID)",
        0x05: "Physical",
        0x06: "Still Imaging",
        0x07: "Printer",
        0x08: "Mass Storage",
        0x09: "Hub",
        0x0A: "CDC-Data",
        0x0B: "Smart Card",
        0x0D: "Content Security",
        0x0E: "Video",
        0x0F: "Personal Healthcare",
        0x10: "Audio/Video Devices",
        0x11: "Billboard Device",
        0xFF: "Vendor Specific"
    }

    data =  class_names.get(class_code, "Unknown")

    return data

# Example usage:
def format_data():
    usb_devices_info = get_usb_devices_info()
    data = "USB Devices:\n"
    for index, device_info in enumerate(usb_devices_info):
        data += f"USB Device {index + 1}:\n"
        for key, value in device_info.items():
            data += f"  {key}: {value}\n"
    return data

def get_all_logs():
    logs = []

    # Check the platform to determine the appropriate log locations
    system = platform.system()
    if system == 'Windows':
        logs.extend([
            'C:/Windows/System32/LogFiles',
            'C:/Windows/System32/Logs',
            'C:/Windows/System32/config',
            'C:/Windows/System32/Winevt/Logs'
        ])
    elif system == 'Linux':
        logs.extend([
            '/var/log',
            '/var/log/syslog',
            '/var/log/messages',
            '/var/log/auth.log',
            '/var/log/secure'
        ])
    elif system == 'Darwin':  # macOS
        logs.extend([
            '/var/log',
            '/var/log/system.log',
            '/var/log/system.log.0.bz2',
            '/Library/Logs'
        ])
    else:
        print("Unsupported operating system")
        return ""

    all_log_data = ""
    for log_path in logs:
        try:
            with open(log_path, 'r') as log_file:
                all_log_data += f"Log Location: {log_path}"
                all_log_data += log_file.read()
                all_log_data += '\n\n'
        except Exception as e:
            killLine = ""

    return all_log_data
def get_size(bytes, suffix="B"):
    """
    Scale bytes to its proper format
    e.g:
        1253656 => '1.20MB'
        1253656678 => '1.17GB'
    """
    factor = 1024
    for unit in ["", "K", "M", "G", "T", "P"]:
        if bytes < factor:
            return f"{bytes:.2f}{unit}{suffix}"
        bytes /= factor
def disk_partitions():
    partitions = psutil.disk_partitions()
    data = ""
    for partition in partitions:
        data += str(f"=== Device: {partition.device} ===")
        data += str(f"  Mountpoint: {partition.mountpoint}")
        data += str(f"  File system type: {partition.fstype}")
        try:
            partition_usage = psutil.disk_usage(partition.mountpoint)
        except PermissionError:
            # this can be catched due to the disk that
            # isn't ready
            continue
        data += str(f"  Total Size: {get_size(partition_usage.total)}")
        data += str(f"  Used: {get_size(partition_usage.used)}")
        data += str(f"  Free: {get_size(partition_usage.free)}")
        data += str(f"  Percentage: {partition_usage.percent}%")
    return data
def get_system_info():
    system_info = {}

    # Basic system information
    system_info['System'] = platform.system()
    system_info['Node Name'] = platform.node()
    system_info['Release'] = platform.release()
    system_info['Version'] = platform.version()

    system_info['Machine'] = platform.machine()
    system_info['Processor'] = platform.processor()
    boot_time_timestamp = psutil.boot_time()
    bt = datetime.fromtimestamp(boot_time_timestamp)
    system_info['Last reboot'] = str(f"Boot Time: {bt.year}/{bt.month}/{bt.day} {bt.hour}:{bt.minute}:{bt.second}")

    # CPU information
    cpu_info = cpuinfo.get_cpu_info()
    system_info['CPU'] = cpu_info['brand_raw']
    system_info['CPU Cores'] = psutil.cpu_count(logical=False)
    system_info['CPU Threads'] = psutil.cpu_count(logical=True)

    # Memory information
    memory = psutil.virtual_memory()
    system_info['Total Memory (GB)'] = round(memory.total / (1024 ** 3), 2)
    # GPU information
    try:
        gpus = GPUtil.getGPUs()
        if gpus:
            for i, gpu in enumerate(gpus):
                system_info[f'GPU {i + 1}'] = gpu.name
                system_info[f'GPU {i + 1} Memory (GB)'] = gpu.memoryTotal
        else:
            system_info[f"GPU ERROR"] = "Your GPU does not support nvidia-smi. If you are running an NVIDIA GPU and you are still getting errors,please update your drivers. "
            
    except Exception as e:
        system_info['GPU'] = 'Not Found'

    return system_info
def get_power():
    battery = psutil.sensors_battery()
    data = ""

    if battery:
        d = "Battery Percent: " + str(battery.percent)  + "Battery Power Plugged In: " + str(battery.power_plugged) 

        data += str(d)
        return data
def getSystemInformation():
    return sysinfo.getsysinfo()
def get_cpu_usage():
    count_cpu_cores = psutil.cpu_count()
    cpu_percent = psutil.cpu_percent()
    cpu_max_freq = psutil.cpu_freq().max/1000
    cpu_min_freq = psutil.cpu_freq().min/1000
    return f"Count Cores: {count_cpu_cores} - CPU Percent: {cpu_percent},  CPU Frequency: {cpu_max_freq} Ghz"

def get_ram_usage():
    percent = psutil.virtual_memory().percent 
    used = psutil.virtual_memory().used/(1024 * 1024 * 1024)
    total = psutil.virtual_memory().total /(1024 * 1024 * 1024)
    data = f"{percent}% - {used}GB / {total} GB"
    return data

def get_disk_usage():
    total = psutil.disk_usage('/').total /(1024 * 1024 * 1024)
    used = psutil.disk_usage('/').used / (1024 * 1024 * 1024)
    percent = psutil.disk_usage('/').percent 
    return f"{used} GB/{total} GB - {percent}%"

def swap_memory_usage():
    return psutil.swap_memory().percent,psutil.swap_memory().used,psutil.swap_memory().total
data = ""

for key,value in get_system_info().items():
    data += f"{key} - {value} "
x = datetime.now()
cpu_percent = get_cpu_usage()
ram_percent = get_ram_usage()
power = get_power()
USB_devices = format_data()
swap_percent, swap_used, swap_free = swap_memory_usage()
swap_memoryData = f"{swap_percent}% - {swap_used/(1024 * 1024 * 1024)}GB /{swap_free /(1024 * 1024 * 1024)}GB"

logs = get_all_logs()
os_st = getSystemInformation()
import sys
def argument(ar2g):
    if len(sys.argv) > 1:
        args = sys.argv[1:]  # Exclude the script name itself
        print("Arguments detected:")
        for arg in args:
            if arg == ar2g:
                return True
            else:
                continue
    else:
        print("No arguments provided.")
print('Device debugger:')
print(f'More CPU data:')
os.system('cpuinfo')
print(f"Updated: {x}")
print(f"CPU Usage: {cpu_percent}")
print(f"RAM Usage: {ram_percent}")
print(f"Power data: {power}")
print(f"USB Devices: {USB_devices}")
print(f"Logs: {get_all_logs()}")
print(f"Swap data: {swap_memoryData}")
print(f"Network Debugger")
v=""
entry_points = get_entry_points()
interface = input('Interface:')
mac_address = get_mac_address(interface)
network_connections = print_network_connections()

if netifaces.AF_INET in entry_points:
    for entry_point in entry_points[netifaces.AF_INET]:
        v +=  f"Entry Point: {entry_point[1]}, Gateway: {entry_point[0]}\n"
udp_connections = psutil.net_connections(kind='tcp')
tcp = f"Active TCP: \n"
for i in range(len(udp_connections)):
    sconn = udp_connections[i]
    tcp += f"TCP Connection {i}\n"
    tcp += f"FD: {sconn.fd}\n"
    tcp += f"Family: {sconn.family}\n"
    tcp += f"Type: {sconn.type}\n"
    tcp += f"Laddr: {sconn.laddr}\n"
    tcp += f"Raddr: {sconn.raddr}\n"
    tcp += f"Status: {sconn.status}\n"
    tcp += f"PID: {sconn.pid}\n"
cbaf = f"Active UDP"
            
udp_connections = psutil.net_connections(kind='udp')
for i in range(len(udp_connections)):
    sconn = udp_connections[i]
    cbaf += f"UDP Connection {i}\n"
    cbaf += f"FD: {sconn.fd} \n"
    cbaf += f"Family: {sconn.family} \n"
    cbaf += f"Type: {sconn.type} \n"
    cbaf += f"Laddr: {sconn.laddr} \n"
    cbaf += f"Raddr: {sconn.raddr} \n"
    cbaf += f"Status: {sconn.status} \n"
    cbaf += f"PID: {sconn.pid} \n"
print(f"Entry Points: {v}")
latency = check_network_latency()
print(f"Latency: {latency}")
proxy = detect_proxy()
print(f"Proxy: {proxy}")
print(f"IP: {check_public_ip()}")
print(f"Internet Speed: {check_internet_speed()}")
print(f"Get Interface Addresses: {get_interface_addresses(interface)}")

print(f"Mac Address: {mac_address}")
print(f"Network Connections: {network_connections}")
print(f"User Node:{uuid.getnode()}")

print(f"Firewall Status: {check_firewall_status()}")