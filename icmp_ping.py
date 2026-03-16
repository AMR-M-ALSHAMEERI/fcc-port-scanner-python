import socket
import struct
import time
import select
import ipaddress
import concurrent.futures

def calculate_checksum(source_string):
    """
    Calculates the checksum for the ICMP packet, required by the protocol.
    """
    sum = 0
    count_to = (len(source_string) // 2) * 2
    count = 0
    while count < count_to:
        this_val = source_string[count + 1] * 256 + source_string[count]
        sum = sum + this_val
        sum = sum & 0xffffffff
        count = count + 2
    if count_to < len(source_string):
        sum = sum + source_string[len(source_string) - 1]
        sum = sum & 0xffffffff
    sum = (sum >> 16) + (sum & 0xffff)
    sum = sum + (sum >> 16)
    answer = ~sum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer

def create_icmp_packet(packet_id):
    """
    Crafts a raw ICMP Echo Request (Type 8) packet.
    """
    # Header is type (8), code (8), checksum (16), id (16), sequence (16)
    header = struct.pack('bbHHh', 8, 0, 0, packet_id, 1)
    # Payload is just the current timestamp
    data = struct.pack('d', time.time())
    
    # Calculate checksum on the complete packet
    my_checksum = calculate_checksum(header + data)
    
    # Repack header with the correct checksum
    header = struct.pack('bbHHh', 8, 0, socket.htons(my_checksum), packet_id, 1)
    
    return header + data

def ping(dest_ip, timeout=1.0):
    """
    Ping a single IP address using raw sockets.
    Returns True if live (Echo Reply received), False if timeout or dead.
    """
    try:
        icmp = socket.getprotobyname("icmp")
    except socket.error:
        icmp = 1 # Fallback to 1 if getprotobyname fails
        
    try:
        # Create raw socket (Requires Administrator Privileges on Windows)
        my_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
    except PermissionError:
        raise PermissionError("Raw sockets require Administrator privileges to run!")
    except socket.error as e:
        if e.errno in (10013, 1): # WSAEACCES or EPERM
            raise PermissionError("Raw sockets require Administrator privileges to run!")
        raise
    
    packet_id = int((id(timeout) * time.time()) % 65535)
    packet = create_icmp_packet(packet_id)
    
    try:
        my_socket.sendto(packet, (dest_ip, 1))
    except socket.gaierror:
        my_socket.close()
        return False
        
    ready = select.select([my_socket], [], [], timeout)
    if ready[0] == []: # Timeout
        my_socket.close()
        return False

    try:
        rec_packet, addr = my_socket.recvfrom(1024)
        icmp_header = rec_packet[20:28]
        type, code, checksum, p_id, sequence = struct.unpack('bbHHh', icmp_header)
        my_socket.close()
        # Verify it's an Echo Reply (Type 0) and matches our packet ID
        if type == 0 and p_id == packet_id:
            return True
    except Exception:
        my_socket.close()

    return False

def ping_sweep(network_cidr, max_workers=100):
    """
    Takes a CIDR string (e.g. 192.168.1.0/24), expands it to all IPs, 
    and returns a sorted list of IPs that are actively replying to ICMP echo requests.
    """
    try:
         # Treat single IPs as /32 blocks
        if '/' not in network_cidr:
            network_cidr += '/32'
        network = ipaddress.ip_network(network_cidr, strict=False)
    except Exception as e:
        raise ValueError(f"Invalid network notation: {e}")
        
    live_hosts = []
    
    def check_host(ip):
        ip_str = str(ip)
        try:
            if ping(ip_str):
                live_hosts.append(ip_str)
        except PermissionError as e:
            raise e
            
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        # network.hosts() skips broadcast and network IDs, but works for /32
        targets = list(network.hosts()) if network.num_addresses > 1 else [network.network_address]
        # execute map and convert to list to catch exceptions
        list(executor.map(check_host, targets))
        
    # Sort for cleaner user output
    sorted_hosts = sorted(live_hosts, key=lambda ip: ipaddress.IPv4Address(ip))
    return sorted_hosts
