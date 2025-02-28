from scapy.all import sniff, IP, TCP, UDP, ICMP

def packet_callback(packet):
    """
    This function is triggered when a packet is captured.
    It extracts and displays relevant information.
    """
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = "OTHER"

        if TCP in packet:
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        elif ICMP in packet:
            protocol = "ICMP"
            src_port = "N/A"
            dst_port = "N/A"
        else:
            src_port = "N/A"
            dst_port = "N/A"

        print(f"[{protocol}] {src_ip}:{src_port} -> {dst_ip}:{dst_port}")

# Sniff packets (root/admin required on some OS)
print("Sniffing network traffic... Press Ctrl+C to stop.")
sniff(prn=packet_callback, store=False)
