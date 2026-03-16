import port_scanner
import argparse
import os

# Define the path for the first-run flag file
FIRST_RUN_FLAG = ".first_run_complete"

def print_banner():
    """Prints the initialization banner with the user's name."""
    print("==================================================")
    print("          INITIALIZING PORT SCANNER V1.0          ")
    print("             Developed by: AMR              ")
    print("==================================================\n")

def main():
    # Set up argparse for command line arguments
    parser = argparse.ArgumentParser(description="FCC Port Scanner: A lightweight TCP port scanner.")
    parser.add_argument("--target", type=str, required=True, help="The target IP address or hostname to scan.")
    parser.add_argument("--ports", type=str, required=True, metavar='PORTS', help="Comma-separated ports and/or ranges (e.g., --ports 20,80,1000-2000).")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output with service identification.")
    parser.add_argument("-o", "--output", type=str, metavar='FILE', help="Save the scan output to a specified text file.")
    parser.add_argument("--sweep", action="store_true", help="Perform an ICMP ping sweep to discover live hosts before port scanning.")
    
    args = parser.parse_args()

    # Check for the first run banner
    if not os.path.exists(FIRST_RUN_FLAG):
        print_banner()
        # Create the flag file so it doesn't run again
        try:
            with open(FIRST_RUN_FLAG, "w") as f:
                f.write("Initialized.")
        except Exception:
            pass # Fail silently if we can't write the file

    # Check if target is a network mask or sweep requested
    is_network = '/' in args.target
    targets_to_scan = []

    if is_network or args.sweep:
        print(f"[*] Initiating Host Discovery (Ping Sweep) on {args.target}...")
        import icmp_ping
        try:
            live_hosts = icmp_ping.ping_sweep(args.target)
            if live_hosts:
                print(f"[+] Discovered {len(live_hosts)} active hosts: {', '.join(live_hosts)}")
            targets_to_scan = live_hosts
        except PermissionError as e:
            print(f"[-] Permission Error: {e}")
            print("[-] Please run your terminal as Administrator to perform Ping Sweeps!")
            return
        except ValueError as e: 
            # If they passed a hostname with --sweep
            print(f"[-] Invalid network syntax: {e}")
            return
    else:
        # Scan normally
        targets_to_scan = [args.target]

    if not targets_to_scan:
        print("[-] No live targets found to scan. Exiting.")
        return

    full_output = ""
    for target in targets_to_scan:
        if args.verbose:
            print(f"\nStarting TCP scan on {target} for ports: {args.ports}...")
        
        result = port_scanner.get_open_ports(target, args.ports, args.verbose)
        if result == "Error: Invalid IP address" or result == "Error: Invalid hostname":
            print(f"[-] Skipping {target}: {result}")
            continue

        res_str = str(result)
        print("\n" + res_str)
        full_output += res_str + "\n\n"

    if args.output:
        try:
            with open(args.output, "w") as f:
                f.write(full_output.strip() + "\n")
            print(f"\n[+] Full results successfully saved to {args.output}")
        except Exception as e:
            print(f"\n[-] Failed to write to {args.output}: {e}")

if __name__ == "__main__":
    main()