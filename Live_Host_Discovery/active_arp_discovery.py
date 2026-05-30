from scapy.all import Ether, sendp, Raw, ARP, srp

frame = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(hwtype=1,op=1,pdst="10.0.2.15/24")
frame.show()

answered, unanswered = srp(frame, timeout=2, verbose=True, iface="eth0")

for snd, rcv in answered:
    print(rcv.psrc, rcv.hwsrc)