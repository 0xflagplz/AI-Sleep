# AI-Driven Beacon Sleep

## Overview

This is a VERY VERY basic implementation of taking a data set to train a model to predict if a sleep setting will be detected by an EDR. This uses a supervised learning model that uses fake data based on detection capability for long term beacon detection. THIS IS NOT MEANT TO BE USED IN A OP.

## Components

### 1. Data Generation (`data-creation/generate.py`)

The `generate.py` script is responsible for generating synthetic data that simulates different operating system versions, EDR types, network conditions, and time of day. This data is used to train and test the AI model.

- **OS Versions**: Windows 10, Windows 11
- **EDR Types**: Includes popular EDR solutions like Crowdstrike Falcon, SentinelOne, and others.
- **Traffic Volumes**: Low, Medium, High
- **Beacon Types**: HTTP, HTTPS, DNS, SMB
- **Time of Day**: Simulated as an hour of the day (0-23)
- **Detection Outcomes**: Detected, Undetected

The script generates a CSV file (`improved_generated_test.csv`) with 8000 rows of data, each containing a combination of the above parameters and a detection outcome.

### 2. Process And Output Model (`scripts/process.py`)

The `process.py` script is responsible for loading, preprocessing, and training a machine learning model using the synthetic data generated. It uses a GradientBoostingClassifier to predict detection outcomes.

- **Data Loading**: Reads data from a CSV file.
- **Preprocessing**: Encodes categorical features (OS Version, EDR Type, Network Load, Beacon Type) and converts string-based numerical columns (Jitter, Initial Sleep Time) to float. It also encodes the 'Detection Outcome' as a binary variable.
- **Data Splitting**: Splits the data into training and test sets.
- **Model Training**: Trains a GradientBoosting model on the training data.
- **Evaluation**: Evaluates the model's accuracy and prints a classification report.
- **Model Saving**: Saves the trained model to a file (`trained_model.joblib`).

### 3. Prediction Model (`bof/prediction.py`)

The `prediction.py` script loads a pre-trained model to predict the detection outcome based on input parameters. It preprocesses the input data, encodes categorical variables, and uses the model to make predictions.

- **Preprocessing**: Encodes OS version, EDR type, network load, beacon type, and considers the time of day.
- **Prediction**: Outputs whether the sleep setting is "Detected" or "Undetected".

### 4. BOF Integration (`bof/sleepinNstuff.cna`)

The BOF scripts (`bof/sleepinNstuff.cna`) integrate the AI model into a security tool, allowing it to execute AI-generated sleep settings.

- **`bof/sleepinNstuff.cna`**: Executes the Python script to generate sleep and jitter settings that will return "Undetected", which are then applied to a beacon session.

## Usage

1. **Data Generation**: Run `generate.py` to create the synthetic dataset.
   ```bash
   python generate.py
   ```

2. **Process Data and Output Model**: Run `process.py` to create the model.
   ```bash
   python scripts/process.py path/to/your_data.csv
   ```

3. **Model Prediction**: Use `prediction.py` to predict detection outcomes based on input parameters.
   ```bash
   python bof/prediction.py <OS Version> <EDR Type> <Beacon Type>
   ```

4. **BOF Execution**: Use the BOF scripts to integrate the AI model into your security tool and apply the generated sleep settings.

## Disclaimer

This project is a proof of concept and uses synthetic data. The AI model is not trained on real-world data and should not be used in production environments.

## Inspiration

0xtriboulet's talk that integrated ai facial recognition to a loader.
