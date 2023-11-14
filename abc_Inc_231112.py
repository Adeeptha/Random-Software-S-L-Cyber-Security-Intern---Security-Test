import re
import os
import re
from datetime import datetime

def get_latest_firewall_log(folder_path):
    # List all files in the specified folder
    files = [f for f in os.listdir(folder_path) if os.path.isfile(os.path.join(folder_path, f))]

    # Filter files that match the format "firewalllog_YYYY_MM_DD.log" or "firewalllog_YYYY_M_D.log"
    firewall_logs = [f for f in files if re.match(r'firewalllog_\d{4}_(0[1-9]|1[0-2])_(0[1-9]|[12][0-9]|3[01])\.log', f) or
                                              re.match(r'firewalllog_\d{4}_(0[1-9]|1[0-2])_(\d{1,2})\.log', f)]

    # If there are no matching files, return None
    if not firewall_logs:
        return None

    # Extract dates from file names and convert them to datetime objects
    dates = [datetime.strptime(re.search(r'(\d{4}_(0[1-9]|1[0-2])_(\d{1,2}))', f).group(1), '%Y_%m_%d') for f in firewall_logs]

    # Find the index of the latest date
    latest_index = dates.index(max(dates))

    # Return the path to the latest firewall log file
    return os.path.join(folder_path, firewall_logs[latest_index])

# Latest file path:
folder_path = 'logs'
latest_firewall_log = get_latest_firewall_log(folder_path)

if latest_firewall_log:
    file_path = f"{latest_firewall_log}"
else:
    print("No firewall log files found in the specified folder.")

# Read the content of the file
with open(file_path, 'r') as file:
    firewall_log = file.read()

def analyze_firewall_log(log_entries):
    results = []

    for entry in log_entries:
        if "BLOCK" in entry.get("Action", ""):
            attack_type = re.search(r"- (.+)$", entry.get("Info", ""))
            if attack_type:
                results.append({
                    "Log Line": entry,
                    "Attack Type": attack_type.group(1).strip()
                })

    return results

# Remove leading and trailing whitespaces from the log file
firewall_log = firewall_log.strip()

# Split the log into lines
log_lines = firewall_log.split('\n')

# Extract field names from the first line
field_names = log_lines[0].split('|')
field_names = [field.strip() for field in field_names]

# Result list to store log entries
result = []

# Process each log entry
for entry in log_lines[1:]:
    # Split the entry into fields using regex to handle spaces in IP addresses and ports
    fields = re.split(r'\s+', entry.strip())

    # Create a dictionary to store the field-value pairs
    log_entry = {}

    # Assign values to the corresponding fields
    for i in range(min(len(field_names), len(fields))):
        log_entry[field_names[i]] = fields[i]

    # Assign everything after the 11th space to the "Info" field
    if len(fields) > len(field_names):
        log_entry["Info"] = ' '.join(fields[len(field_names)-1:])

    # Append the log entry to the result list
    result.append(log_entry)

# Analyze the logs
analysis_results = analyze_firewall_log(result)

# Print the expected output
for idx, result in enumerate(analysis_results, start=1):
    print(f"{idx}.{result['Attack Type']}:\nLog Line: {result['Log Line']}\nAnalysis: This log line indicates {result['Attack Type']}.\n")
