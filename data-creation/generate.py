import csv
import random

# Define the parameters for data generation
os_versions = ["Windows 10", "Windows 11"]
build_numbers = ["19042", "19043", "19044", "22000", "22621"]
traffic_volumes = ["Low", "Medium", "High"]
detection_outcomes = ["Detected", "Undetected"]

# EDR types and their base detection chances
edr_types = [
    "Crowdstrike Falcon",
    "SentinelOne",
    "Microsoft Defender for Endpoint",
    "VMware Carbon Black Cloud",
    "FireEye Endpoint Security",
    "McAfee MVISION",
    "Palo Alto Networks Cortex XDR",
    "Zscaler Cloud Protection",
    "Splunk Phantom EDR",
    "Symantec Endpoint Protection",
    "Windows Defender",
    "Trend Micro Apex One",
    "Sophos Intercept X",
    "Check Point Harmony Endpoint",
    "Trend Micro Deep Security",
    "Fortinet FortiEDR",
    "Cisco Secure Endpoint",
    "ESET Enterprise Inspector",
    "Kaspersky Endpoint Security",
    "Bitdefender GravityZone"
]

# Base detection chance per EDR type
base_detection_chance = {
    "Crowdstrike Falcon": 0.6,
    "SentinelOne": 0.6,
    "Microsoft Defender for Endpoint": 0.5,
    "VMware Carbon Black Cloud": 0.5,
    "FireEye Endpoint Security": 0.5,
    "McAfee MVISION": 0.5,
    "Palo Alto Networks Cortex XDR": 0.5,
    "Zscaler Cloud Protection": 0.5,
    "Splunk Phantom EDR": 0.5,
    "Symantec Endpoint Protection": 0.4,
    "Windows Defender": 0.4,
    "Trend Micro Apex One": 0.4,
    "Sophos Intercept X": 0.4,
    "Check Point Harmony Endpoint": 0.4,
    "Trend Micro Deep Security": 0.4,
    "Fortinet FortiEDR": 0.4,
    "Cisco Secure Endpoint": 0.4,
    "ESET Enterprise Inspector": 0.4,
    "Kaspersky Endpoint Security": 0.3,
    "Bitdefender GravityZone": 0.3
}

# Group EDRs by their sleep sensitivity
high_sensitivity_edrs = ["Crowdstrike Falcon", "SentinelOne"]
medium_sensitivity_edrs = [
    "Microsoft Defender for Endpoint",
    "VMware Carbon Black Cloud",
    "FireEye Endpoint Security",
    "McAfee MVISION",
    "Palo Alto Networks Cortex XDR",
    "Zscaler Cloud Protection",
    "Splunk Phantom EDR"
]
lower_sensitivity_edrs = [
    "Symantec Endpoint Protection",
    "Windows Defender",
    "Trend Micro Apex One",
    "Sophos Intercept X",
    "Check Point Harmony Endpoint",
    "Trend Micro Deep Security",
    "Fortinet FortiEDR",
    "Cisco Secure Endpoint",
    "ESET Enterprise Inspector"
]
weak_detection_edrs = ["Kaspersky Endpoint Security", "Bitdefender GravityZone"]

# Function to determine detection outcome based on criteria
def determine_detection(sleep_time, traffic_volume, edr_type, os_version):
    detection_chance = base_detection_chance[edr_type]
    
    # EDR-specific logic
    if edr_type in high_sensitivity_edrs:
        if sleep_time >= 120:
            detection_chance -= 0.3  # Less likely to be detected with sleeps ≥2 minutes
        else:
            detection_chance += 0.3  # More likely to be detected with sleeps <2 minutes
    elif edr_type in medium_sensitivity_edrs:
        if sleep_time >= 10:
            detection_chance -= 0.3  # Less likely to be detected with sleeps ≥10 sec
        else:
            detection_chance += 0.3  # More likely to be detected with sleeps <10 sec
    elif edr_type in lower_sensitivity_edrs:
        if sleep_time >= 10:
            detection_chance -= 0.2  # Less likely to be detected with sleeps ≥10 sec
        else:
            detection_chance += 0.2  # More likely to be detected with sleeps <10 sec
    elif edr_type in weak_detection_edrs:
        if sleep_time < 5:
            detection_chance += 0.1  # Slightly more likely to detect very short sleeps
        else:
            detection_chance -= 0.1  # Even less likely to detect longer sleeps

    # Traffic volume logic
    if traffic_volume == "Low":
        if sleep_time < 60:
            detection_chance += 0.2  # In low traffic, short sleeps are more likely to be detected
        else:
            detection_chance -= 0.1  # Longer sleeps less likely to be detected
    elif traffic_volume == "High":
        if sleep_time < 60:
            detection_chance -= 0.1  # In high traffic, short sleeps are less likely to be detected
        else:
            detection_chance += 0.1  # Longer sleeps slightly more likely to be detected

    # OS version logic for Default Antivirus (Windows Defender)
    if edr_type == "Windows Defender":
        if os_version == "Windows 10":
            detection_chance -= 0.2  # Windows 10 DefaultAV is worse at detection
        elif os_version == "Windows 11":
            detection_chance += 0.1  # Windows 11 DefaultAV is better at detection
    else:
        # Other EDRs detect the same on Windows 10 and 11
        pass

    # Ensure detection_chance is between 0 and 1
    detection_chance = min(max(detection_chance, 0), 1)

    # Determine detection outcome based on probability
    if random.random() < detection_chance:
        return "Detected"
    else:
        return "Undetected"

# Generate data
data = []
for _ in range(8000):  # Generate 100 rows of data
    os_version = random.choice(os_versions)
    build_number = random.choice(build_numbers)
    edr = random.choice(edr_types)
    initial_sleep_time = random.randint(1, 270)  # Sleep time between 1 second and 4 minutes
    jitter = random.randint(0, 50)  # Jitter between 0% and 50%
    traffic_volume = random.choice(traffic_volumes)
    detection_outcome = determine_detection(initial_sleep_time, traffic_volume, edr, os_version)
    
    data.append([
        os_version,
        build_number,
        edr,
        f"{initial_sleep_time} seconds",
        f"{jitter}%",
        traffic_volume,
        detection_outcome
    ])

# Write to CSV
with open('generated_test.csv', 'w', newline='') as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(["OS Version", "Build Number", "EDR Type", "Initial Sleep Time", "Jitter", "Network Load", "Detection Outcome"])
    writer.writerows(data)

print("Data generation complete. Check 'generated_test.csv'.")
