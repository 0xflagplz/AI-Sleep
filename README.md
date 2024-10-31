# AI-Driven Sleep Detection Prediction

## Overview

This project involves the creation of a basic AI model using synthetic data to predict whether a sleep setting would be detected by various Endpoint Detection and Response (EDR) systems. The model is integrated into a Beacon Object File (BOF) to dynamically generate sleep and jitter settings for use in a security context.

## Components

### 1. Data Generation (`generate.py`)

The `generate.py` script is responsible for generating synthetic data that simulates different operating system versions, EDR types, and network conditions. This data is used to train and test the AI model.

- **OS Versions**: Windows 10, Windows 11
- **EDR Types**: Includes popular EDR solutions like Crowdstrike Falcon, SentinelOne, and others.
- **Traffic Volumes**: Low, Medium, High
- **Detection Outcomes**: Detected, Undetected

The script generates a CSV file (`generated_test.csv`) with 8000 rows of data, each containing a combination of the above parameters and a detection outcome.

### 2. Prediction Model (`prediction.py`)

The `prediction.py` script loads a pre-trained model to predict the detection outcome based on input parameters. It preprocesses the input data, encodes categorical variables, and uses the model to make predictions.

- **Preprocessing**: Encodes OS version, EDR type, and network load.
- **Prediction**: Outputs whether the sleep setting is "Detected" or "Undetected".

### 3. BOF Integration (`test.cna` and `example.cna`)

The BOF scripts (`test.cna` and `example.cna`) integrate the AI model into a security tool, allowing it to execute AI-generated sleep settings.

- **`test.cna`**: Executes the Python script to generate sleep and jitter settings, which are then applied to a beacon session.
- **`example.cna`**: Provides a user interface to execute the prediction script and apply the settings.

## Usage

1. **Data Generation**: Run `generate.py` to create the synthetic dataset.
   ```bash
   python generate.py
   ```

2. **Model Prediction**: Use `prediction.py` to predict detection outcomes based on input parameters.
   ```bash
   python prediction.py <OS Version> <EDR Type>
   ```

3. **BOF Execution**: Use the BOF scripts to integrate the AI model into your security tool and apply the generated sleep settings.

## Disclaimer

This project is a proof of concept and uses synthetic data. The AI model is not trained on real-world data and should not be used in production environments.

## License

This project is licensed under the MIT License.
