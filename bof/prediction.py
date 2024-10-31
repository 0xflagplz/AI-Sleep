import pandas as pd
from joblib import load
import sys
import random
import os
import datetime
import numpy as np

# Determine the directory of the current script
script_dir = os.path.dirname(os.path.abspath(__file__))

# Load the saved model and preprocessors from the script's directory
model_data = load(os.path.join(script_dir, 'trained_model.joblib'))
model = model_data['model']
scaler = model_data['scaler']
one_hot_encoder = model_data['one_hot_encoder']
numerical_features = model_data['numerical_features']

# Preprocess input data
def preprocess_input(data):
    """Prepare incoming data for prediction."""
    # Clean 'Sleep' and 'Jitter' columns
    data['Sleep'] = data['Sleep'].str.replace(' seconds', '').astype(float)
    data['Jitter'] = data['Jitter'].str.replace('%', '').astype(float)

    # Calculate 'Effective Sleep'
    data['Effective Sleep'] = data['Sleep'] + (data['Sleep'] * data['Jitter'] / 100)

    # Create interaction features
    def create_interaction_features(X):
        # Interaction between OS Version and EDR Type
        os_edr_interaction = X['OS Version'] + "_" + X['EDR Type']
        # Interaction between Network Load and Beacon Type
        network_beacon_interaction = X['Network Load'] + "_" + X['Beacon Type']
        return pd.DataFrame({
            'os_edr_interaction': os_edr_interaction,
            'network_beacon_interaction': network_beacon_interaction
        })

    interaction_df = create_interaction_features(data)

    # Combine all categorical features including interactions
    categorical_features = ['OS Version', 'EDR Type', 'Network Load', 'Beacon Type']
    all_categorical = pd.concat([data[categorical_features], interaction_df], axis=1)

    # Apply one-hot encoding to categorical features using the loaded encoder
    categorical_encoded = one_hot_encoder.transform(all_categorical)

    # Prepare numerical features
    # Ensure that numerical features are in the same order as during training
    numerical_data = data[numerical_features].values

    # Combine categorical and numerical features
    X = np.hstack([categorical_encoded, numerical_data])

    # Apply scaling to features using the loaded scaler
    X_scaled = scaler.transform(X)

    return X_scaled

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

    # Define a mapping for EDR types
    edr_type_mapping = {
        'Crowdstrike': 'Crowdstrike Falcon',
        'Sentinelone': 'SentinelOne',
        'MDE': 'Microsoft Defender for Endpoint',
        'VMware': 'VMware Carbon Black Cloud',
        'Fireeye': 'FireEye Endpoint Security',
        'Mcafee': 'McAfee MVISION',
        'Paloalto': 'Palo Alto Networks Cortex XDR',
        'Zscaler': 'Zscaler Cloud Protection',
        'Splunk': 'Splunk Phantom EDR',
        'Symantec': 'Symantec Endpoint Protection',
        'Defender': 'Windows Defender',
        'Trendmicro': 'Trend Micro Apex One',
        'Sophos': 'Sophos Intercept X',
        'Checkpoint': 'Check Point Harmony Endpoint',
        'TrendmicroDP': 'Trend Micro Deep Security',
        'Fortinet': 'Fortinet FortiEDR',
        'Cisco': 'Cisco Secure Endpoint',
        'ESET': 'ESET Enterprise Inspector',
        'Kaspersky': 'Kaspersky Endpoint Security',
        'Bitdefender': 'Bitdefender GravityZone',
    }

    # Define a list of possible Beacon Types
    beacon_types = ["HTTP", "HTTPS", "DNS", "SMB"]

    # Get command-line arguments
    if len(sys.argv) != 4:
        print("Usage: python predict.py <OS Version> <EDR Type> <Beacon Type>")
        sys.exit(1)

    os_version_input = sys.argv[1]
    edr_type_input = sys.argv[2]
    beacon_type = sys.argv[3]

    if beacon_type not in beacon_types:
        print("Invalid Beacon Type. Please choose from: HTTP, HTTPS, DNS, SMB")
        sys.exit(1)

    os_version = os_version_mapping.get(os_version_input, os_version_input)

    # Adjust build number based on OS version
    if os_version_input == '10':
        build_number = '19044'
    elif os_version_input == '11':
        build_number = '22621'
    else:
        build_number = 'Unknown'  # Default or error handling

    edr_type = edr_type_mapping.get(edr_type_input, edr_type_input)

    # Get current hour
    hour_of_day = datetime.datetime.now().hour

    # Iterate over possible values for sleep and jitter
    sleep = 60  # Start with the minimum sleep time
    while sleep <= 600:  # Continue until the maximum sleep time
        jitter = random.randint(0, 50)  # Random jitter between 0 and 50%

        input_data = pd.DataFrame({
            'OS Version': [os_version],
            'Build Number': [build_number],
            'EDR Type': [edr_type],
            'Sleep': [f"{sleep} seconds"],
            'Jitter': [f"{jitter}%"],
            'Network Load': ['Low'],  # Adjust as needed
            'Beacon Type': [beacon_type],
            'Hour of Day': [hour_of_day]
        })

        result = predict_outcome(input_data)
        if result[0] == "Undetected":
            print(f"{sleep} {jitter}")
            sys.exit(0)
        else:
            sleep += 20  # Increment sleep time by 10 seconds

    print("No undetected configuration found.")
