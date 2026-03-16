import socket
import concurrent.futures
from common_ports import ports_and_services

def parse_ports(port_input):
    """
    Parses a string or a list into a sorted list of unique integers.
    Supports comma-separated values (80,443) and ranges (1000-2000).
    """
    if isinstance(port_input, list):
        if len(port_input) == 2 and port_input[0] <= port_input[1]:
            # Backwards compatibility for the original list format [start, end]
            return list(range(port_input[0], port_input[1] + 1))
        return port_input
        
    ports = set()
    parts = str(port_input).split(',')
    
    for part in parts:
        part = part.strip()
        if not part:
            continue
        if '-' in part:
            try:
                start, end = map(int, part.split('-'))
                ports.update(range(start, end + 1))
            except ValueError:
                pass # Ignore malformed ranges
        else:
            try:
                ports.add(int(part))
            except ValueError:
                pass # Ignore malformed single ports
                
    return sorted(list(ports))

def get_open_ports(target, port_range, verbose=False):
    ip = ""
    hostname = ""
    open_ports = []

    # 1. VALIDATION AND RESOLUTION
    try:
        # Check if the target is an IP or Hostname
        # gethostbyname works for both, but we need to know which one was provided
        ip = socket.gethostbyname(target)
        
        # If the input was an IP, try to get the hostname for verbose mode
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except socket.herror:
            hostname = "" # No hostname found for this IP
            
        # If the target input was already the hostname, save it
        if target != ip:
            hostname = target
            
    except socket.gaierror:
        # If it's a non-IP string that doesn't resolve
        if any(c.isalpha() for c in target):
            return "Error: Invalid hostname"
        return "Error: Invalid IP address"
    except socket.error:
        return "Error: Invalid IP address"

    # 2. SCANNING LOOP
    ports_to_scan = parse_ports(port_range)
    grabbed_banners = {}
    
    def check_port(port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0) # 1 second is standard for FCC tests
        is_open = s.connect_ex((ip, port)) == 0
        banner = None
        if is_open:
            try:
                s.settimeout(0.5)
                # Try receiving first for services like SSH/FTP
                try:
                    banner_data = s.recv(1024)
                except socket.timeout:
                    # If timeout, send an HTTP payload to trigger a response
                    s.send(b"GET / HTTP/1.1\r\n\r\n")
                    banner_data = s.recv(1024)
                
                if banner_data:
                    text = banner_data.decode('utf-8', errors='ignore').strip()
                    if text:
                        # Grab the first line of the banner, limited to 30 characters
                        banner = text.split('\n')[0][:30].strip()
            except Exception:
                pass
        s.close()
        return (port, banner) if is_open else None
        
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        results = executor.map(check_port, ports_to_scan)
        for res in results:
            if res is not None:
                p, banner = res
                open_ports.append(p)
                if banner:
                    grabbed_banners[p] = banner

    # 3. OUTPUT FORMATTING
    if not verbose:
        return open_ports

    # VERBOSE MODE
    # Header logic: "Open ports for URL (IP)" or just "Open ports for IP"
    if hostname:
        header = f"Open ports for {hostname} ({ip})\n"
    else:
        header = f"Open ports for {ip}\n"
    
    body = "PORT     SERVICE"
    for port in open_ports:
        service = ports_and_services.get(port, "unknown")
        banner = grabbed_banners.get(port)
        if banner:
            service = f"{service} [{banner}]"
        # {port:<9} aligns the text to the left with a width of 9 spaces
        body += f"\n{port:<9}{service}"

    return header + body