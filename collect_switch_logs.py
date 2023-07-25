import os
import logging
from netmiko import ConnectHandler
from concurrent.futures import ThreadPoolExecutor
import gzip

# Configure logging
logging.basicConfig(filename="switch_logs_collection.log", level=logging.DEBUG,
                    format="%(asctime)s - %(levelname)s - %(message)s")

def collect_switch_logs(ip_address, username, password, enable_password=None, log_filters=None):
    try:
        # Specify the device type and create the Netmiko SSH connection
        device = {
            "device_type": "cisco_ios",  # Update this for different switch vendors
            "host": ip_address,
            "username": username,
            "password": password,
            "secret": enable_password
        }
        net_connect = ConnectHandler(**device)

        # Enter privileged mode if applicable
        if enable_password:
            net_connect.enable()

        # Execute commands to retrieve switch logs (adjust commands based on the vendor)
        logs_commands = [
            "show logging",  # Example: Cisco IOS command to show system logs
            # Add more commands specific to your switch vendor and model
        ]
        switch_logs = ""
        for command in logs_commands:
            log_output = net_connect.send_command(command)
            switch_logs += f"\n{command}\n{log_output}\n"

        # Disconnect from the device
        net_connect.disconnect()

        # Apply log filtering if specified
        if log_filters:
            filtered_logs = [log_line for log_line in switch_logs.splitlines() if any(filter in log_line for filter in log_filters)]
            switch_logs = "\n".join(filtered_logs)

        return switch_logs

    except Exception as e:
        logging.error(f"Error collecting logs from {ip_address}: {e}")
        return None

def save_logs_to_file(ip_address, switch_logs, output_directory):
    output_file_path = os.path.join(output_directory, f"switch_logs_{ip_address}.txt")
    with open(output_file_path, "w") as file:
        file.write(switch_logs)

def compress_logs(output_directory):
    # Compress each log file using gzip
    for filename in os.listdir(output_directory):
        if filename.endswith(".txt"):
            file_path = os.path.join(output_directory, filename)
            with open(file_path, "rb") as file:
                compressed_file_path = os.path.join(output_directory, f"{filename}.gz")
                with gzip.open(compressed_file_path, "wb") as compressed_file:
                    compressed_file.writelines(file)

def collect_switch_logs_for_ips(switch_ips, username, password, enable_password=None, log_filters=None):
    with ThreadPoolExecutor() as executor:
        futures = []
        for switch_ip in switch_ips:
            future = executor.submit(collect_switch_logs, switch_ip, username, password, enable_password, log_filters)
            futures.append(future)

        switch_logs_dict = {}
        for future, switch_ip in zip(futures, switch_ips):
            switch_logs = future.result()
            if switch_logs:
                switch_logs_dict[switch_ip] = switch_logs
            else:
                logging.warning(f"Failed to collect logs from {switch_ip}.")
        
        return switch_logs_dict

def main():
    # Replace these variables with your switch details
    switch_ips = ["192.168.1.1", "192.168.1.2", "192.168.1.3"]
    switch_username = "admin"
    switch_password = "password123"
    enable_password = "enablepass123"  # Only required for devices with privilege levels (e.g., Cisco)

    output_directory = "logs_output"

    # Create output directory if it does not exist
    os.makedirs(output_directory, exist_ok=True)

    # Optionally, specify log filters to extract specific log entries
    log_filters = ["%SYS-5-CONFIG_I", "LINK-3-UPDOWN"]

    # Collect logs from switches using multi-threading
    switch_logs_dict = collect_switch_logs_for_ips(switch_ips, switch_username, switch_password, enable_password, log_filters)

    # Save logs to separate files for each switch
    for switch_ip, switch_logs in switch_logs_dict.items():
        save_logs_to_file(switch_ip, switch_logs, output_directory)
        print(f"Logs collected and saved for {switch_ip}.")

    # Optionally, compress the log files
    compress_logs(output_directory)

if __name__ == "__main__":
    main()
