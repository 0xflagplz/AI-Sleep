import csv
import random
import math

# Define the parameters for data generation
os_versions = ["Windows 10", "Windows 11"]
build_numbers = ["19042", "19043", "19044", "22000", "22621"]
detection_outcomes = ["Detected", "Undetected"]
beacon_types = ["HTTP", "HTTPS", "DNS", "SMB"]

# Traffic volumes will be determined based on time of day
traffic_volumes = ["Low", "Medium", "High"]

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
def determine_detection(sleep_time, jitter, traffic_volume, edr_type, os_version, beacon_type, hour_of_day):
    detection_chance = base_detection_chance[edr_type]
    
    # EDR-specific logic
    if edr_type in high_sensitivity_edrs:
        if sleep_time >= 300:
            detection_chance -= 0.4  # Sleeps ≥5 minutes are much less likely to be detected
        elif sleep_time >= 120:
            detection_chance -= 0.2  # Sleeps between 2-5 minutes are less likely to be detected
        elif sleep_time < 60:
            detection_chance += 0.3  # Sleeps <1 minute are more likely to be detected
    elif edr_type in medium_sensitivity_edrs:
        if sleep_time >= 120:
            detection_chance -= 0.3
        elif sleep_time < 60:
            detection_chance += 0.2
    elif edr_type in lower_sensitivity_edrs:
        if sleep_time >= 60:
            detection_chance -= 0.2
        elif sleep_time < 60:
            detection_chance += 0.1
    elif edr_type in weak_detection_edrs:
        if sleep_time < 60:
            detection_chance += 0.05
        else:
            detection_chance -= 0.1

    # Jitter logic
    if jitter >= 30:
        detection_chance -= 0.1  # High jitter reduces detection chance
    elif jitter <= 10:
        detection_chance += 0.1  # Low jitter increases detection chance

    # Traffic volume logic
    if traffic_volume == "Low":
        detection_chance += 0.1  # Anomalous activities are more noticeable
    elif traffic_volume == "High":
        detection_chance -= 0.1  # Anomalies are less noticeable

    # OS version logic for Windows Defender
    if edr_type == "Windows Defender":
        if os_version == "Windows 10":
            detection_chance -= 0.1  # Windows 10 Defender is less effective
        elif os_version == "Windows 11":
            detection_chance += 0.1  # Windows 11 Defender is more effective

    # Beacon type logic
    if beacon_type == "DNS":
        detection_chance -= 0.15  # DNS beacons are less detectable
    elif beacon_type == "HTTPS":
        detection_chance -= 0.05  # HTTPS beacons are slightly less detectable
    elif beacon_type == "SMB":
        detection_chance += 0.1  # SMB beacons are more detectable

    # Time of day logic
    if 8 <= hour_of_day <= 18:
        detection_chance += 0.05  # Higher monitoring during business hours
    else:
        detection_chance -= 0.05  # Lower monitoring during off-hours

    # Ensure detection_chance is between 0 and 1
    detection_chance = min(max(detection_chance, 0), 1)

    # Determine detection outcome based on probability
    if random.random() < detection_chance:
        return "Detected"
    else:
        return "Undetected"

# Generate data
data = []
for _ in range(8000):  # Generate 8000 rows of data
    os_version = random.choice(os_versions)
    build_number = random.choice(build_numbers)
    
    # Correlate EDR with OS version
    if os_version == "Windows 10":
        edr = random.choices(
            edr_types,
            weights=[0.7 if "Windows Defender" in edr else 0.3 for edr in edr_types],
            k=1
        )[0]
    else:
        edr = random.choice(edr_types)
    
    # Simulate time of day (0 to 23 hours)
    hour_of_day = random.randint(0, 23)

    # Determine traffic volume based on time of day
    if 8 <= hour_of_day <= 18:  # Typical working hours
        traffic_volume = random.choices(
            ["Medium", "High"], weights=[0.4, 0.6], k=1
        )[0]
    else:  # Off-peak hours
        traffic_volume = random.choices(
            ["Low", "Medium"], weights=[0.7, 0.3], k=1
        )[0]
    
    # Adjust beacon type probabilities based on network load
    if traffic_volume == "High":
        beacon_type = random.choices(
            beacon_types, weights=[0.1, 0.1, 0.3, 0.5], k=1
        )[0]
    elif traffic_volume == "Medium":
        beacon_type = random.choices(
            beacon_types, weights=[0.2, 0.3, 0.3, 0.2], k=1
        )[0]
    else:  # Low traffic
        beacon_type = random.choices(
            beacon_types, weights=[0.4, 0.4, 0.1, 0.1], k=1
        )[0]
    
    # Generate sleep time using an exponential distribution
    initial_sleep_time = int(random.expovariate(1/180))  # Mean of 180 seconds
    initial_sleep_time = max(60, min(initial_sleep_time, 600))  # Clamp between 60 and 600 seconds

    # Generate jitter using a normal distribution
    jitter = int(random.normalvariate(30, 10))  # Mean of 30%, std dev of 10%
    jitter = max(0, min(jitter, 50))  # Clamp between 0% and 50%
    
    detection_outcome = determine_detection(
        initial_sleep_time, jitter, traffic_volume, edr, os_version, beacon_type, hour_of_day
    )
    
    data.append([
        os_version,
        build_number,
        edr,
        f"{initial_sleep_time} seconds",
        f"{jitter}%",
        traffic_volume,
        beacon_type,
        hour_of_day,
        detection_outcome
    ])

# Write to CSV
with open('improved_generated_test.csv', 'w', newline='') as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow([
        "OS Version", "Build Number", "EDR Type", "Sleep", "Jitter", "Network Load", 
        "Beacon Type", "Hour of Day", "Detection Outcome"
    ])
    writer.writerows(data)

print("Improved data generation complete. Check 'improved_generated_test.csv'.")
