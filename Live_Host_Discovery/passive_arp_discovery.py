from scapy.all import sniff, ARP

def arp_discovery(pkt):
    if ARP in pkt and pkt[ARP].op == 2:
        print(f"IP: {pkt[ARP].psrc} MAC: {pkt[ARP].hwsrc}")

sniff(filter="arp", prn=arp_discovery, store=0, iface='eth0')