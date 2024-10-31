import pandas as pd
from joblib import load
from sklearn.preprocessing import LabelEncoder
import sys
import random
import os

# Determine the directory of the current script
script_dir = os.path.dirname(os.path.abspath(__file__))

# Load the saved model from the script's directory
model_path = os.path.join(script_dir, 'trained_model.joblib')
model = load(model_path)
label_encoder_os = LabelEncoder()
label_encoder_edr = LabelEncoder()
label_encoder_network = LabelEncoder()

# Preprocess input data
def preprocess_input(data):
    """Prepare incoming data for prediction."""
    # Encode categorical columns
    data['OS Version'] = label_encoder_os.fit_transform(data['OS Version'])
    data['EDR Type'] = label_encoder_edr.fit_transform(data['EDR Type'])
    data['Network Load'] = label_encoder_network.fit_transform(data['Network Load'])

    # Convert 'Jitter' column to numerical
    data['Jitter'] = data['Jitter'].str.extract(r'(\d+)').astype(float)

    # Convert 'Initial Sleep Time' to numerical
    data['Initial Sleep Time'] = data['Initial Sleep Time'].str.extract(r'(\d+)').astype(float)
    return data

# Predict function
def predict_outcome(input_data):
    # Preprocess input data
    processed_data = preprocess_input(input_data)
    
    # Predict using the loaded model
    prediction = model.predict(processed_data)
    
    return ["Detected" if p == 1 else "Undetected" for p in prediction]

# Main function
if __name__ == "__main__":
    # Define a mapping for OS versions
    os_version_mapping = {
        '10': 'Windows 10',
        '11': 'Windows 11',
    }
    #write immediate execution to log file in directory
    with open('log.txt', 'w') as f:
        f.write(f"Executing prediction.py with arguments: {sys.argv[1]} {sys.argv[2]}")
        f.close()

    # Get command-line arguments
    if len(sys.argv) != 3:
        print("error")
        sys.exit(1)

    os_version_input = sys.argv[1]
    edr_type_input = sys.argv[2]

    os_version = os_version_mapping.get(os_version_input, os_version_input)

    # Adjust build number based on OS version
    if os_version_input == '10':
        build_number = '19044'
    elif os_version_input == '11':
        build_number = '22621'
    else:
        build_number = 'Unknown'  # Default or error handling

    # Define a mapping for EDR types
    edr_type_mapping = {
        'Crowdstrike': 'Crowdstrike Falcon',
        'SentinelOne': 'SentinelOne',
        'MDE': 'Microsoft Defender for Endpoint',
        'VMware': 'VMware Carbon Black Cloud',
        'FireEye': 'FireEye Endpoint Security',
        'McAfee': 'McAfee MVISION',
        'PaloAlto': 'Palo Alto Networks Cortex XDR',
        'Zscaler': 'Zscaler Cloud Protection',
        'Splunk': 'Splunk Phantom EDR',
        'Symantec': 'Symantec Endpoint Protection',
        'WindowsDefender': 'Windows Defender',
        'Trend Micro': 'Trend Micro Apex One',
        'Sophos': 'Sophos Intercept X',
        'Check Point': 'Check Point Harmony Endpoint',
        'Trend Micro Deep Security': 'Trend Micro Deep Security',
        'Fortinet': 'Fortinet FortiEDR',
        'Cisco': 'Cisco Secure Endpoint',
        'ESET': 'ESET Enterprise Inspector',
        'Kaspersky': 'Kaspersky Endpoint Security',
        'Bitdefender': 'Bitdefender GravityZone',
    }

    edr_type = edr_type_mapping.get(edr_type_input, edr_type_input)

    # Iterate over possible values for sleep and jitter
    while True:  # Use a loop to continuously test random values
        sleep = random.randint(5, 300)  # Random sleep time between 5 and 300
        jitter = random.randint(0, 70)  # Random jitter between 0 and 70

        input_data = pd.DataFrame({
            'OS Version': [os_version],
            'Build Number': [build_number],  # Example build number
            'EDR Type': [edr_type],
            'Initial Sleep Time': [f"{sleep} seconds"],
            'Jitter': [f"{jitter}%"],
            'Network Load': ['Low']  # Example network load
        })

        result = predict_outcome(input_data)
        if result[0] == "Undetected":
            print(f"{sleep} {jitter}")
            sys.exit(0)

    print("error")
