import argparse
from scapy.all import IP, TCP, sr1
from concurrent.futures import ThreadPoolExecutor
from random import randint
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def syn_scan(ip, port):
    sport = randint(50000, 60000)
    packet = IP(dst=ip) / TCP(
        dport=port,
        sport=sport,
        flags="S"
    )

    response = sr1(packet, timeout=2, verbose=False)

    if response is None:
        return (port, "Filtered")

    elif response.haslayer(TCP):
        if response[TCP].flags == 0x12: 
            rst_packet = IP(dst=ip) / TCP(
                dport=port,
                sport=sport,
                flags="R",
                seq=response[TCP].ack,
                ack=response[TCP].seq + 1
            )
            sr1(rst_packet, timeout=1, verbose=False)
            
            return (port, "Open")

        elif response[TCP].flags == 0x14:  # RST-ACK
            return (port, "Closed")
            
    return (port, "Unknown")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="A simple multi-threaded TCP SYN port scanner using Scapy.")
    
    parser.add_argument("ip", help="The target IP address to scan.")
    
    parser.add_argument("-s", "--start", type=int, default=1, help="Starting port (default: 1)")
    parser.add_argument("-e", "--end", type=int, default=1024, help="Ending port (default: 1024)")
    parser.add_argument("-t", "--threads", type=int, default=20, help="Number of concurrent worker threads (default: 20)")

    args = parser.parse_args()

    ports = range(args.start, args.end + 1)

    print(f"\nStarting SYN scan on {args.ip}...")
    print(f"Scanning ports {args.start} to {args.end} using {args.threads} threads.\n")
    print(f"{'PORT':<10}{'STATUS':<10}")
    print("-" * 20)

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        results = executor.map(lambda p: syn_scan(args.ip, p), ports)

    for result in results:
        if result: # Ensure result is not None
            port, status = result
            print(f"{port:<10}{status:<10}")