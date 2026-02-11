import port_scanner

# 1. Test a simple IP scan (Should return a list of numbers)
print("Testing IP Scan:")
ports = port_scanner.get_open_ports("209.216.230.240", [440, 445])
print(f"Open ports: {ports}\n")

# 2. Test a URL scan with Verbose Mode (Should return the pretty table)
print("Testing Verbose URL Scan:")
verbose_report = port_scanner.get_open_ports("scanme.nmap.org", [20, 80], True)
print(verbose_report + "\n")

# 3. Test Invalid Hostname
print("Testing Invalid Hostname:")
err1 = port_scanner.get_open_ports("scanme.nmap.org-invalid", [22, 443])
print(f"Result: {err1}\n")

# 4. Test Invalid IP
print("Testing Invalid IP:")
err2 = port_scanner.get_open_ports("209.216.230.777", [22, 443])
print(f"Result: {err2}\n")

# Run unit tests automatically
import unittest
from test_module import UnitTests

if __name__ == "__main__":
    # This runs the tests in test_module.py
    unittest.main()