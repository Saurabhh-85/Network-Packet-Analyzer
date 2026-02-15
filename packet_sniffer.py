from scapy.all import sniff, IP, TCP, UDP, Raw

def process_packet(packet):
    print("\n--- Packet Captured ---")

    if packet.haslayer(IP):
        ip_layer = packet[IP]
        print("Source IP:", ip_layer.src)
        print("Destination IP:", ip_layer.dst)

        # Protocol detection
        if packet.haslayer(TCP):
            print("Protocol: TCP")
        elif packet.haslayer(UDP):
            print("Protocol: UDP")
        else:
            print("Protocol: Other")

        # Payload data
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            print("Payload:", payload[:50])  # show first 50 bytes


print("Starting Packet Sniffer...")
print("Press CTRL+C to stop.\n")

sniff(prn=process_packet, store=False)
