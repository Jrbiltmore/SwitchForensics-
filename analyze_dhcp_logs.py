import re
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns

def parse_dhcp_logs(log_file):
    # Regular expression pattern to extract relevant information from DHCP logs
    dhcp_log_pattern = r"(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}).*?(?P<ip_address>\d+\.\d+\.\d+\.\d+).*?(?P<mac_address>([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})).*?(?P<hostname>\S+).*?(?P<action>added|released)"

    # Read DHCP log file and extract log entries
    with open(log_file, "r") as file:
        log_entries = re.findall(dhcp_log_pattern, file.read())

    return log_entries

def analyze_dhcp_logs(log_entries):
    # Convert log_entries to a pandas DataFrame for further analysis
    columns = ["Timestamp", "IP Address", "MAC Address", "Hostname", "Action"]
    df = pd.DataFrame(log_entries, columns=columns)

    # Convert timestamp string to datetime object
    df["Timestamp"] = pd.to_datetime(df["Timestamp"])

    # Perform advanced statistical analysis
    dhcp_summary = df.groupby("Action").size()
    unique_macs = df["MAC Address"].nunique()
    unique_ips = df["IP Address"].nunique()

    # Calculate the time difference between consecutive DHCP actions for each IP-MAC pair
    df["Time_Difference"] = df.groupby(["IP Address", "MAC Address"])["Timestamp"].diff().dt.total_seconds()

    # Calculate mean and standard deviation of time difference
    mean_time_diff = df["Time_Difference"].mean()
    std_time_diff = df["Time_Difference"].std()

    # Identify DHCP lease durations
    df["Lease_Duration"] = df["Timestamp"].diff().dt.total_seconds()
    mean_lease_duration = df["Lease_Duration"].mean()

    # Detect potential DHCP conflicts
    potential_conflicts = df[df.duplicated(subset=["IP Address"], keep=False)]

    return df, dhcp_summary, unique_macs, unique_ips, mean_time_diff, std_time_diff, mean_lease_duration, potential_conflicts

def visualize_dhcp_data(df):
    # Visualize the DHCP action timestamps using a box plot
    plt.figure(figsize=(8, 6))
    sns.boxplot(x="Action", y="Time_Difference", data=df)
    plt.title("DHCP Action Timestamps")
    plt.xlabel("Action")
    plt.ylabel("Time Difference (seconds)")
    plt.show()

def generate_summary_report(dhcp_summary, unique_macs, unique_ips, mean_time_diff, std_time_diff, mean_lease_duration):
    # Generate a summary report with key insights
    summary_report = f"""DHCP Log Summary:
    Added: {dhcp_summary['added']}
    Released: {dhcp_summary['released']}
    Total Unique MAC Addresses: {unique_macs}
    Total Unique IP Addresses: {unique_ips}
    Mean Time Difference between Consecutive DHCP Actions: {mean_time_diff:.2f} seconds
    Standard Deviation of Time Difference: {std_time_diff:.2f} seconds
    Mean DHCP Lease Duration: {mean_lease_duration:.2f} seconds
    """

    return summary_report

def main():
    # Replace this variable with the path to your DHCP log file
    dhcp_log_file = "dhcp_logs.txt"

    # Parse DHCP logs and analyze the data
    log_entries = parse_dhcp_logs(dhcp_log_file)
    if log_entries:
        df, dhcp_summary, unique_macs, unique_ips, mean_time_diff, std_time_diff, mean_lease_duration, potential_conflicts = analyze_dhcp_logs(log_entries)

        # Visualize DHCP data
        visualize_dhcp_data(df)

        # Generate and print summary report
        summary_report = generate_summary_report(dhcp_summary, unique_macs, unique_ips, mean_time_diff, std_time_diff, mean_lease_duration)
        print(summary_report)

        # Print potential DHCP conflicts
        if not potential_conflicts.empty:
            print("\nPotential DHCP Conflicts:")
            print(potential_conflicts)

        print("\nDHCP Log Data:")
        print(df)
    else:
        print("No valid DHCP log entries found in the log file.")

if __name__ == "__main__":
    main()
