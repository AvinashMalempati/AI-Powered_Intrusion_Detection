import pandas as pd
import numpy as np
import joblib
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, OneHotEncoder, LabelEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.metrics import accuracy_score, classification_report
from tensorflow.keras.models import Model
from tensorflow.keras.layers import Input, Dense
from tensorflow.keras.optimizers import Adam
from xgboost import XGBClassifier
import glob

# ----------------------------
# Critical Cleaning Parameters
# ----------------------------
drop_columns = [
    "Flow ID", "Source IP", "Src IP", "Source Port", "Src Port",
    "Destination IP", "Dst IP", "Bwd PSH Flags", "Fwd URG Flags",
    "Bwd URG Flags", "CWE Flag Count", "Fwd Avg Bytes/Bulk", "Fwd Byts/b Avg",
    "Fwd Avg Packets/Bulk", "Fwd Pkts/b Avg", "Fwd Avg Bulk Rate", "Fwd Blk Rate Avg",
    "Bwd Avg Bytes/Bulk", "Bwd Byts/b Avg", "Bwd Avg Packets/Bulk", "Bwd Pkts/b Avg",
    "Bwd Avg Bulk Rate", "Bwd Blk Rate Avg", 'Fwd Header Length.1'
]

mapper = {
    'Dst Port': 'Destination Port',
    'Tot Fwd Pkts': 'Total Fwd Packets',
    'Tot Bwd Pkts': 'Total Backward Packets',
    'TotLen Fwd Pkts': 'Fwd Packets Length Total',
    'TotLen Bwd Pkts': 'Bwd Packets Length Total',
    'Fwd Pkt Len Max': 'Fwd Packet Length Max',
    'Fwd Pkt Len Min': 'Fwd Packet Length Min',
    'Fwd Pkt Len Mean': 'Fwd Packet Length Mean',
    'Fwd Pkt Len Std': 'Fwd Packet Length Std',
    'Bwd Pkt Len Max': 'Bwd Packet Length Max',
    'Bwd Pkt Len Min': 'Bwd Packet Length Min',
    'Bwd Pkt Len Mean': 'Bwd Packet Length Mean',
    'Bwd Pkt Len Std': 'Bwd Packet Length Std',
    'Flow Byts/s': 'Flow Bytes/s',
    'Flow Pkts/s': 'Flow Packets/s',
    'Fwd IAT Tot': 'Fwd IAT Total',
    'Bwd IAT Tot': 'Bwd IAT Total',
    'Fwd Header Len': 'Fwd Header Length',
    'Bwd Header Len': 'Bwd Header Length',
    'Pkt Size Avg': 'Avg Packet Size'
}

# ---------------
# Load & Clean Data
# ---------------
# Specify the directory where the CSV files are located
directory = '/Users/avinash/Documents/capstone Project/datasets/MachineLearningCVE'

# Use glob to get all CSV files in the directory and subdirectories
csv_files = glob.glob(f'{directory}/**/*.csv', recursive=True)

# Create an empty list to store cleaned dataframes
dfs = []

# Loop through each CSV file
for file in csv_files:
    try:
        # Read the file into a DataFrame
        df = pd.read_csv(file, skipinitialspace=True, encoding='latin')

        # Skip empty DataFrames
        if df.empty:
            continue

        # Rename columns for standardization
        df.rename(columns=mapper, inplace=True)

        # Drop unnecessary columns
        df.drop(columns=drop_columns, inplace=True, errors='ignore')

        # Handle timestamps if present
        if 'Timestamp' in df.columns:
            df['Timestamp'] = pd.to_datetime(df['Timestamp'], errors='coerce')
            df['Timestamp'] = df['Timestamp'].apply(
                lambda x: x + pd.Timedelta(hours=12) if x is not pd.NaT and x.hour < 8 else x
            )
            df.sort_values(by=['Timestamp'], inplace=True)

        # Standardize the 'Label' column
        if 'Label' in df.columns:
            df['Label'].replace({'BENIGN': 'Benign'}, inplace=True)
            df['Label'] = df['Label'].astype('category')

        # Handle invalid values
        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        df.dropna(inplace=True)

        # Optimize numeric data types
        numeric_cols = df.select_dtypes(include=['number']).columns
        df[numeric_cols] = df[numeric_cols].apply(pd.to_numeric, errors='coerce', downcast='float')

        # Drop duplicate rows
        df.drop_duplicates(subset=df.columns.difference(['Label', 'Timestamp']), inplace=True)

        # Add cleaned DataFrame to the list
        dfs.append(df)

    except Exception as e:
        print(f"Error processing file {file}: {e}")

# Combine all cleaned dataframes into one
df = pd.concat(dfs, ignore_index=True) if dfs else pd.DataFrame()
print("Combined DataFrame:")
print(df.info())

# Ensure column names are stripped
df.columns = df.columns.str.strip()

# Encode the 'Label' column with numerical values
if 'Label' in df.columns:
    label_encoder = LabelEncoder()
    df['Label'] = label_encoder.fit_transform(df['Label'])
    print("Unique Labels (and their encoded values):", dict(enumerate(label_encoder.classes_)))
else:
    raise ValueError("The 'Label' column is missing in the DataFrame.")

# ----------------------------
# Preparing Data for Training
# ----------------------------
# Separate features (X) and target (y)
X = df.drop(columns=['Label'], errors='ignore')
y = df['Label']

# Split data into training and testing datasets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)

# Define a preprocessing pipeline
numerical_features = X.select_dtypes(include=['number']).columns
categorical_features = X.select_dtypes(include=['object']).columns

preprocessor = ColumnTransformer(
    transformers=[
        ('num', StandardScaler(), numerical_features),
        ('cat', OneHotEncoder(handle_unknown='ignore'), categorical_features)
    ],
    remainder='drop'
)

# Fit transformer to training data and transform both train and test sets
X_train = preprocessor.fit_transform(X_train)
X_test = preprocessor.transform(X_test)

# Save the preprocessor for future use
joblib.dump(preprocessor, "preprocessor.joblib")

# ------------------------
# Build Autoencoder Model
# ------------------------
input_dim = X_train.shape[1]

input_layer = Input(shape=(input_dim,))
encoded = Dense(64, activation='relu')(input_layer)
encoded = Dense(32, activation='relu')(encoded)
encoded = Dense(16, activation='relu')(encoded)

decoded = Dense(32, activation='relu')(encoded)
decoded = Dense(64, activation='relu')(decoded)
decoded = Dense(input_dim, activation='sigmoid')(decoded)

autoencoder = Model(input_layer, decoded)
autoencoder.compile(optimizer=Adam(learning_rate=0.001), loss='mse')

# Train Autoencoder
autoencoder.fit(X_train, X_train, epochs=20, batch_size=64, validation_data=(X_test, X_test), verbose=1)

# Save Autoencoder
autoencoder.save("autoencoder_model.h5")

# Use encoder part of autoencoder for feature extraction
encoder = Model(input_layer, encoded)
X_train_encoded = encoder.predict(X_train)
X_test_encoded = encoder.predict(X_test)

# ------------------------
# Train XGBoost Classifier
# ------------------------
xgb_model = XGBClassifier(objective='multi:softmax', eval_metric='mlogloss', use_label_encoder=False)
xgb_model.fit(X_train_encoded, y_train)

# Save XGBoost model
joblib.dump(xgb_model, "xgboost_model.joblib")

# Evaluate Model
y_pred = xgb_model.predict(X_test_encoded)
accuracy = accuracy_score(y_test, y_pred)

print("\nModel Accuracy:", accuracy)
print("Classification Report:\n", classification_report(y_test, y_pred, target_names=label_encoder.classes_))
