import os
import logging
import paramiko
from netmiko import ConnectHandler
from concurrent.futures import ThreadPoolExecutor

# Configure logging
logging.basicConfig(filename="switch_extraction.log", level=logging.DEBUG,
                    format="%(asctime)s - %(levelname)s - %(message)s")

def extract_switch_configuration(ip_address, username, password, enable_password=None):
    try:
        # Specify the device type and create the Netmiko SSH connection
        device = {
            "device_type": "cisco_ios"  # Update this for different switch vendors
            "host": ip_address,
            "username": username,
            "password": password,
            "secret": enable_password
        }
        net_connect = ConnectHandler(**device)

        # Enter privileged mode if applicable
        if enable_password:
            net_connect.enable()

        # Execute the command to retrieve the switch configuration
        switch_config = net_connect.send_command("show running-config")

        # Disconnect from the device
        net_connect.disconnect()

        return switch_config

    except Exception as e:
        logging.error(f"Error extracting configuration from {ip_address}: {e}")
        return None

def save_config_to_file(ip_address, switch_config, output_directory):
    output_file_path = os.path.join(output_directory, f"switch_config_{ip_address}.txt")
    with open(output_file_path, "w") as file:
        file.write(switch_config)

def extract_switch_logs(ip_address, username, password):
    # Implement code to extract switch logs if applicable (vendor-specific).
    # Remember to configure logging for logging messages related to switch logs extraction.

def main():
    # Replace these variables with your switch details
    switch_ips = ["192.168.1.1", "192.168.1.2", "192.168.1.3"]
    switch_username = "admin"
    switch_password = "password123"
    enable_password = "enablepass123"  # Only required for devices with privilege levels (e.g., Cisco)

    output_directory = "output"

    # Create output directory if it does not exist
    os.makedirs(output_directory, exist_ok=True)

    # Set up a ThreadPoolExecutor for parallel extraction
    with ThreadPoolExecutor() as executor:
        futures = []
        for switch_ip in switch_ips:
            future = executor.submit(extract_switch_configuration, switch_ip, switch_username, switch_password, enable_password)
            futures.append(future)

        for future, switch_ip in zip(futures, switch_ips):
            switch_configuration = future.result()
            if switch_configuration:
                save_config_to_file(switch_ip, switch_configuration, output_directory)
                print(f"Switch configuration extracted and saved for {switch_ip}.")
                # Optionally, extract switch logs
                extract_switch_logs(switch_ip, switch_username, switch_password)
            else:
                print(f"Failed to extract switch configuration for {switch_ip}.")

if __name__ == "__main__":
    main()
