import re
import threading
import pandas as pd
import matplotlib.pyplot as plt
from netmiko import ConnectHandler
from concurrent.futures import ThreadPoolExecutor

def retrieve_arp_table(device_platform, device_ip, username, password):
    # Specify device connection details
    device = {
        "device_type": device_platform,
        "ip": device_ip,
        "username": username,
        "password": password,
    }

    try:
        # Connect to the device
        with ConnectHandler(**device) as net_connect:
            # Get ARP table output
            arp_table_output = net_connect.send_command("show arp")
    except Exception as e:
        print(f"Error connecting to {device_ip}: {e}")
        return None

    return arp_table_output

def parse_arp_table(arp_table_output, device_platform):
    # Dictionary of regular expression patterns for different device platforms
    arp_patterns = {
        "cisco_ios": r"Internet\s+(\d+\.\d+\.\d+\.\d+)\s+\w+\s+(\w{4}\.\w{4}\.\w{4})\s+ARPA\s+(\S+)",
        # Add more patterns for other platforms if needed
    }

    arp_entries = []

    # Select the appropriate regular expression pattern based on the device platform
    arp_pattern = arp_patterns.get(device_platform.lower())
    if arp_pattern:
        arp_entries = re.findall(arp_pattern, arp_table_output)

    return arp_entries

def analyze_arp_table(arp_table_entries):
    # Perform advanced analysis on ARP table entries
    # For demonstration purposes, we'll print the ARP entries
    for entry in arp_table_entries:
        ip_address, mac_address, interface = entry
        print(f"IP Address: {ip_address}, MAC Address: {mac_address}, Interface: {interface}")

def process_device(device_info):
    device_ip, platform, username, password = device_info
    arp_table_output = retrieve_arp_table(platform, device_ip, username, password)
    if arp_table_output:
        arp_table_entries = parse_arp_table(arp_table_output, platform)
        if arp_table_entries:
            analyze_arp_table(arp_table_entries)
            return arp_table_entries
    return None

def main():
    # Replace these lists with your network device information
    device_ips = ["192.168.1.1", "192.168.1.2", "192.168.1.3"]
    device_platform = "cisco_ios"  # Change if using different platforms
    usernames = ["username1", "username2", "username3"]
    passwords = ["password1", "password2", "password3"]

    # Create a list of device information tuples for multithreading
    devices_info = zip(device_ips, [device_platform] * len(device_ips), usernames, passwords)

    # Use ThreadPoolExecutor for multithreading to fetch ARP tables concurrently
    with ThreadPoolExecutor() as executor:
        arp_table_entries_list = list(executor.map(process_device, devices_info))

    # Merge the ARP table entries from all devices into a single DataFrame for analysis
    arp_table_entries_all = [entry for entries in arp_table_entries_list if entries for entry in entries]
    if arp_table_entries_all:
        arp_df = pd.DataFrame(arp_table_entries_all, columns=["IP Address", "MAC Address", "Interface"])
        print("\nMerged ARP Table Entries from All Devices:")
        print(arp_df)

        # Plot a pie chart to visualize MAC addresses distribution
        mac_count = arp_df["MAC Address"].value_counts()
        plt.figure(figsize=(8, 8))
        plt.pie(mac_count, labels=mac_count.index, autopct="%1.1f%%")
        plt.title("MAC Address Distribution")
        plt.axis("equal")
        plt.show()

if __name__ == "__main__":
    main()
