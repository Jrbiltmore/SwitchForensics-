import os
import re
import pandas as pd
import matplotlib.pyplot as plt

def read_log_file(log_file_path):
    # Read and return the content of a log file
    with open(log_file_path, "r") as file:
        log_content = file.read()
    return log_content

def analyze_log_file(log_content):
    # Implement log analysis here (e.g., search for keywords, patterns, anomalies)
    # For demonstration purposes, let's search for the words "error" and "attack" in the log content
    error_count = log_content.lower().count("error")
    attack_count = log_content.lower().count("attack")
    return error_count, attack_count

def analyze_timeline(log_files):
    # Analyze the timeline of log files (timestamps)
    timeline_data = []
    for log_file_path in log_files:
        log_content = read_log_file(log_file_path)
        timestamp_match = re.search(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", log_content)
        if timestamp_match:
            timestamp = pd.to_datetime(timestamp_match.group(), format="%Y-%m-%d %H:%M:%S")
            timeline_data.append({"Log File": os.path.basename(log_file_path), "Timestamp": timestamp})
    timeline_df = pd.DataFrame(timeline_data)
    timeline_df.sort_values(by="Timestamp", inplace=True)
    return timeline_df

def generate_forensic_report(log_files, incident_id):
    # Analyze log files and timeline data
    analysis_results = []
    for log_file_path in log_files:
        log_content = read_log_file(log_file_path)
        error_count, attack_count = analyze_log_file(log_content)
        analysis_results.append({"Log File": os.path.basename(log_file_path), "Errors Found": error_count, "Attacks Found": attack_count})
    
    timeline_df = analyze_timeline(log_files)

    # Generate the forensic report
    report = f"Forensic Report for Incident ID: {incident_id}\n\n"
    report += "Log Files Analysis:\n"
    report += pd.DataFrame(analysis_results).to_string(index=False)
    report += "\n\nTimeline Analysis:\n"
    report += timeline_df.to_string(index=False)
    
    # Data visualization - bar chart for error and attack counts
    plt.figure(figsize=(8, 6))
    plt.bar(analysis_results[0].keys()[1:], analysis_results[0].values()[1:], color=["blue", "red"])
    plt.title("Log Files Analysis")
    plt.xlabel("Log File")
    plt.ylabel("Count")
    plt.legend(analysis_results[0].keys()[1:])
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.show()

    return report

def main():
    # Replace these variables with the paths to your log files and incident ID
    log_files = ["path/to/log_file1.txt", "path/to/log_file2.txt", "path/to/log_file3.txt"]
    incident_id = "INC123456"

    # Generate the forensic report
    report = generate_forensic_report(log_files, incident_id)

    # Print the report to the console
    print(report)

    # Optionally, save the report to a file
    with open(f"{incident_id}_forensic_report.txt", "w") as file:
        file.write(report)

if __name__ == "__main__":
    main()
