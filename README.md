# Random-Software-S-L-Cyber-Security-Intern---Security-Test

#Simple Firewall Log Analyzing script

This project involves the development of a Simple Firewall Log Analyzing script for ABC Inc., a mid-sized software development company. ABC has recently faced multiple cyber-attacks and, in response, aims to proactively monitor their network traffic for potential threats. The company employs a Linux-based infrastructure, with most servers on-premise and critical services hosted on AWS. The IT security team seeks an efficient mechanism to analyze firewall logs, enhancing their ability to detect anomalies, identify patterns of malicious activity, and fortify the network against attacks.

#Key Objectives of the project 

Detect and Respond to Threats - The script is designed to identify and respond to potential threats in real-time.

Understand Traffic Patterns - ABC aims to improve its understanding of network traffic patterns through log analysis.

Improve Network Security - The insights gained from the logs should inform adjustments to firewall rules, strengthening the network's security posture.

Compliance - The project ensures compliance with industry regulations mandating the monitoring and analysis of security logs.

#How It Works 

Latest Log Retrieval - The script fetches the latest firewall log file from a specified folder containing logs formatted as "firewalllog_YYYY_MM_DD.log" or "firewalllog_YYYY_M_D.log."

Log Analysis - The script processes the log entries, focusing on those with "BLOCK" in the "Action" field. It extracts relevant information, such as attack types, from the "Info" field.

Results Presentation - The script presents the analysis results, including attack types and corresponding log lines, in a meaningful way for easy comprehension.

#Expected Outcome 

A preliminary version of the script that successfully processes a sample log file, detects potential threats, and provides clear analysis results. The script aids the security team in evaluating and adjusting firewall rules to enhance network protection.

