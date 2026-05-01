import subprocess
import re

domain = input('Enter the target domain: ')

if not re.match(r"^[a-zA-Z0-9.-]+$", domain):
    print("Invalid Domain")
    exit()

print("Initiating ICMP Echo packets to check server availibility-----------------------")

try:
    ping_result = subprocess.run(
        ["ping", "-c", "5", domain], 
        capture_output=True, 
        text=True,
        timeout=15)

    if ping_result.returncode == 0:
        print("Output:")
        print(ping_result.stdout)
    else:
        print("Ping failed:")
        print(ping_result.stderr)
except subprocess.TimeoutExpired:
    print("Ping Command Timed Out!")

print("ICMP Echo service stopped----------------------------------------------------------")
