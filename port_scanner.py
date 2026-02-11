import socket
from common_ports import ports_and_services

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
    for port in range(port_range[0], port_range[1] + 1):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0) # 1 second is standard for FCC tests
        
        if s.connect_ex((ip, port)) == 0:
            open_ports.append(port)
        s.close()

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
        # {port:<9} aligns the text to the left with a width of 9 spaces
        body += f"\n{port:<9}{service}"

    return header + body