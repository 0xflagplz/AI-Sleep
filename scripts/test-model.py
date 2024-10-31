import pandas as pd
from joblib import load
from sklearn.preprocessing import LabelEncoder

# Load the saved model
model = load('trained_model.joblib')
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
    data['Jitter'] = data['Jitter'].str.extract('(\d+)').astype(float)

    # Convert 'Sleep' to numerical
    data['Sleep'] = data['Sleep'].str.extract('(\d+)').astype(float)
    return data

# Predict function
def predict_outcome(input_data):
    # Preprocess input data
    processed_data = preprocess_input(input_data)
    
    # Predict using the loaded model
    prediction = model.predict(processed_data)
    return ["Detected" if p == 1 else "Undetected" for p in prediction]

# Example usage
if __name__ == "__main__":
    # Define a mapping for OS versions
    os_version_mapping = {
        '10': 'Windows 10',
        '11': 'Windows 11',
        # Add more mappings as needed
    }


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

    # Ask for user input
    os_version_input = input("Enter OS Version (e.g., 10 for Windows 10): ")
    os_version = os_version_mapping.get(os_version_input, os_version_input)  # Translate input if possible
    build_number = int(input("Enter Build Number (e.g., 22621): "))
    edr_type_input = input("Enter EDR Type (e.g., Zscaler): ")
    edr_type = edr_type_mapping.get(edr_type_input, edr_type_input)  # Translate input if possible
    initial_sleep_time = input("Enter Sleep (e.g., 69 seconds): ")
    jitter = input("Enter Jitter (e.g., 43%): ")
    network_load = input("Enter Network Load (e.g., Low): ")

    # Create an input data frame from user input
    input_data = pd.DataFrame({
        'OS Version': [os_version],
        'Build Number': [build_number],
        'EDR Type': [edr_type],
        'Sleep': [initial_sleep_time],
        'Jitter': [jitter],
        'Network Load': [network_load]
    })

    # Predict outcome
    result = predict_outcome(input_data)
    print("Prediction:", result[0])  # Outputs "Detected" or "Undetected"
