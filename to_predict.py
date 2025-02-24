import pandas as pd
import numpy as np
import joblib
from tensorflow.keras.models import load_model
from sklearn.metrics import classification_report

# File paths for models and CSV file
PREPROCESSOR_PATH = "/Users/avinash/Documents/capstone Project/preprocessor.joblib"  # Path to the preprocessor
AUTOENCODER_MODEL_PATH = "/Users/avinash/Documents/capstone Project/autoencoder_model.h5"  # Path to the autoencoder model
XGBOOST_MODEL_PATH = "/Users/avinash/Documents/capstone Project/xgboost_model.joblib"  # Path to the XGBoost model
CSV_FILE_PATH = "/Users/avinash/Documents/capstone Project/packet_features.csv"  # CSV file with extracted features
OUTPUT_PREDICTIONS = "predictions.csv"  # File to store predictions


def predict_from_csv():
    try:
        # Step 1: Load the CSV data
        print("Loading data from CSV...")
        data = pd.read_csv(CSV_FILE_PATH)

        print(f"Data loaded successfully with shape: {data.shape}")
        print("Columns in the dataset:", data.columns)

        # Step 2: Load the saved preprocessor
        print("Loading preprocessor...")
        preprocessor = joblib.load(PREPROCESSOR_PATH)

        # Preprocess the data using the saved preprocessor
        print("Applying preprocessing to the data...")
        X_processed = preprocessor.transform(data)

        # Step 3: Load the autoencoder
        print("Loading autoencoder model...")
        autoencoder = load_model(AUTOENCODER_MODEL_PATH)

        # Use the encoder part of the autoencoder to reduce dimensionality
        print("Extracting features using the encoder...")
        encoder = autoencoder  # In this example, autoencoder acts as the encoder
        X_encoded = encoder.predict(X_processed)

        # Step 4: Load the XGBoost model
        print("Loading XGBoost model...")
        xgb_model = joblib.load(XGBOOST_MODEL_PATH)

        # Perform predictions using the XGBoost model
        print("Making predictions...")
        predictions = xgb_model.predict(X_encoded)

        # Save predictions to a CSV file
        print("Saving predictions...")
        output = pd.DataFrame({
            "Packet_Index": data.index,
            "Predicted_Label": predictions
        })
        output.to_csv(OUTPUT_PREDICTIONS, index=False)
        print(f"Predictions saved to {OUTPUT_PREDICTIONS}")

        # (Optional) Generate a classification report if ground truth is available
        # Uncomment the next lines if `true_labels` are known
        # true_labels = data["Label"]  # Replace with the actual name of the label column
        # print("Classification Report:")
        # print(classification_report(true_labels, predictions))

    except Exception as e:
        print(f"An error occurred during prediction: {e}")


if __name__ == "__main__":
    predict_from_csv()
