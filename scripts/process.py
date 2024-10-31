import pandas as pd
import sys
from joblib import dump

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.preprocessing import LabelEncoder

# Usage: python train_model.py path/to/your_data.csv

def load_data(file_path):
    """Load data from CSV file."""
    data = pd.read_csv(file_path)
    print("Data Loaded Successfully")
    print("Sample Data:\n", data.head())
    return data

def preprocess_data(data):
    """Encode categorical features and prepare target variable."""
    # Initialize LabelEncoder
    label_encoder = LabelEncoder()

    # Encode categorical columns
    data['OS Version'] = label_encoder.fit_transform(data['OS Version'])
    data['EDR Type'] = label_encoder.fit_transform(data['EDR Type'])
    data['Network Load'] = label_encoder.fit_transform(data['Network Load'])

    # Check if 'Jitter' column exists
    if 'Jitter' in data.columns:
        # Convert 'Jitter' column from string to numerical
        data['Jitter'] = data['Jitter'].str.extract('(\d+)').astype(float)
    else:
        print("Warning: 'Jitter' column is missing.")

    # Convert 'Initial Sleep Time' from string to numerical
    if 'Initial Sleep Time' in data.columns:
        data['Initial Sleep Time'] = data['Initial Sleep Time'].str.extract('(\d+)').astype(float)
    else:
        print("Warning: 'Initial Sleep Time' column is missing.")

    # Encode 'Detection Outcome' as binary (1 = Detected, 0 = Undetected)
    data['Detection Outcome'] = data['Detection Outcome'].apply(lambda x: 1 if x == 'Detected' else 0)

    # Separate features (X) and target (y)
    X = data.drop('Detection Outcome', axis=1)
    y = data['Detection Outcome']
    print("Data Preprocessing Complete")
    return X, y

def split_data(X, y):
    """Split the data into training and test sets."""
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    print("Data Split Complete")
    return X_train, X_test, y_train, y_test

def train_model(X_train, y_train):
    """Train a RandomForest model."""
    model = RandomForestClassifier(random_state=42)
    model.fit(X_train, y_train)
    print("Model Training Complete")
    return model

def evaluate_model(model, X_test, y_test):
    """Evaluate model accuracy and print the classification report."""
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"Model Accuracy: {accuracy}")
    print("\nClassification Report:\n", classification_report(y_test, y_pred))

def main(file_path):
    # Step 1: Load Data
    data = load_data(file_path)

    # Step 2: Preprocess Data
    X, y = preprocess_data(data)

    # Step 3: Split Data
    X_train, X_test, y_train, y_test = split_data(X, y)

    # Step 4: Train Model
    model = train_model(X_train, y_train)

    # Step 5: Evaluate Model
    evaluate_model(model, X_test, y_test)

    # Step 6: Save the trained model
    dump(model, 'trained_model.joblib')
    print("Model saved to 'trained_model.joblib'")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python train_model.py path/to/your_data.csv")
    else:
        main(sys.argv[1])

