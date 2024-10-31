import pandas as pd
import sys
from joblib import dump

from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import FunctionTransformer
import numpy as np
from imblearn.over_sampling import SMOTE

# Usage: python train_model.py path/to/your_data.csv

def load_data(file_path):
    """Load data from CSV file."""
    data = pd.read_csv(file_path)
    print("Data Loaded Successfully")
    print("Sample Data:\n", data.head())
    return data

def preprocess_data(data):
    """Encode features and prepare target variable."""
    # Clean 'Sleep' and 'Jitter' columns
    data['Sleep'] = data['Sleep'].str.replace(' seconds', '').astype(float)
    data['Jitter'] = data['Jitter'].str.replace('%', '').astype(float)
    
    # Calculate effective sleep time considering jitter
    data['Effective Sleep'] = data['Sleep'] + (data['Sleep'] * data['Jitter'] / 100)

    # Define categorical and numerical features
    categorical_features = ['OS Version', 'EDR Type', 'Network Load', 'Beacon Type']
    numerical_features = ['Sleep', 'Jitter', 'Effective Sleep', 'Hour of Day']

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
    all_categorical = pd.concat([data[categorical_features], interaction_df], axis=1)

    # Apply one-hot encoding to categorical features
    one_hot_encoder = OneHotEncoder(sparse_output=False, handle_unknown='ignore')
    categorical_encoded = one_hot_encoder.fit_transform(all_categorical)

    # Prepare numerical features
    numerical_data = data[numerical_features].values

    # Combine categorical and numerical features
    X = np.hstack([categorical_encoded, numerical_data])

    # Encode 'Detection Outcome' as binary (1 = Detected, 0 = Undetected)
    y = data['Detection Outcome'].apply(lambda x: 1 if x == 'Detected' else 0)

    print("Data Preprocessing Complete")
    return X, y, one_hot_encoder, numerical_features

def split_data(X, y):
    """Split the data into training and test sets."""
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    print("Data Split Complete")
    return X_train, X_test, y_train, y_test

def train_model(X_train, y_train):
    """Train a GradientBoosting model with hyperparameter tuning."""
    # Handle imbalanced data
    smote = SMOTE(random_state=42)
    X_train_res, y_train_res = smote.fit_resample(X_train, y_train)

    # Feature scaling for numerical features
    scaler = StandardScaler()
    X_train_res = scaler.fit_transform(X_train_res)

    # Hyperparameter tuning
    param_grid = {
        'n_estimators': [100, 200],
        'max_depth': [3, 5],
        'learning_rate': [0.01, 0.1]
    }
    model = GradientBoostingClassifier(random_state=42)
    grid_search = GridSearchCV(model, param_grid, cv=5, scoring='accuracy')
    grid_search.fit(X_train_res, y_train_res)

    print("Best parameters found: ", grid_search.best_params_)
    print("Model Training Complete")
    return grid_search.best_estimator_, scaler

def evaluate_model(model, scaler, X_test, y_test):
    """Evaluate model accuracy and print the classification report."""
    # Apply scaling to test data
    X_test = scaler.transform(X_test)

    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"Model Accuracy: {accuracy}")
    print("\nClassification Report:\n", classification_report(y_test, y_pred))

def main(file_path):
    # Step 1: Load Data
    data = load_data(file_path)

    # Step 2: Preprocess Data
    X, y, one_hot_encoder, numerical_features = preprocess_data(data)

    # Step 3: Split Data
    X_train, X_test, y_train, y_test = split_data(X, y)

    # Step 4: Train Model
    model, scaler = train_model(X_train, y_train)

    # Step 5: Evaluate Model
    evaluate_model(model, scaler, X_test, y_test)

    # Step 6: Save the trained model and preprocessors
    dump({
        'model': model,
        'scaler': scaler,
        'one_hot_encoder': one_hot_encoder,
        'numerical_features': numerical_features
    }, 'trained_model.joblib')
    print("Model and preprocessors saved to 'trained_model.joblib'")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python train_model.py path/to/your_data.csv")
    else:
        main(sys.argv[1])
