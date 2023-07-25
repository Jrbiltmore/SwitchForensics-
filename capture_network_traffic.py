import os
import datetime
from scapy.all import sniff, wrpcap, Ether, ARP, IP, TCP, UDP

def packet_callback(packet):
    # Get the packet's Ethernet frame
    eth_frame = Ether(packet)

    # Process packets of interest (e.g., ARP, IP, TCP, UDP)
    if ARP in eth_frame:
        arp_packet = eth_frame[ARP]
        print(f"ARP Packet: Source IP: {arp_packet.psrc}, Destination IP: {arp_packet.pdst}")
    elif IP in eth_frame:
        ip_packet = eth_frame[IP]
        if TCP in ip_packet:
            tcp_packet = ip_packet[TCP]
            print(f"TCP Packet: Source IP: {ip_packet.src}, Destination IP: {ip_packet.dst}, Source Port: {tcp_packet.sport}, Destination Port: {tcp_packet.dport}")
        elif UDP in ip_packet:
            udp_packet = ip_packet[UDP]
            print(f"UDP Packet: Source IP: {ip_packet.src}, Destination IP: {ip_packet.dst}, Source Port: {udp_packet.sport}, Destination Port: {udp_packet.dport}")
        else:
            print(f"IP Packet: Source IP: {ip_packet.src}, Destination IP: {ip_packet.dst}")

def capture_traffic(interface, output_directory, max_packets=None):
    try:
        # Create the output directory if it does not exist
        os.makedirs(output_directory, exist_ok=True)

        packet_count = 0
        if max_packets is None:
            # Continuously capture traffic
            sniff(iface=interface, prn=packet_callback)
        else:
            # Capture a specific number of packets
            packets = sniff(iface=interface, count=max_packets, prn=packet_callback)

            # Save the captured packets to a PCAP file
            output_file_path = os.path.join(output_directory, f"captured_packets_{datetime.datetime.now().isoformat()}.pcap")
            wrpcap(output_file_path, packets)

    except Exception as e:
        print(f"Error capturing traffic: {e}")

def main():
    # Replace these variables with your desired settings
    interface = "eth0"  # Replace with the name of your network interface
    output_directory = "captured_traffic"
    max_packets = 100  # Set to None to capture traffic indefinitely

    capture_traffic(interface, output_directory, max_packets)

if __name__ == "__main__":
    main()
