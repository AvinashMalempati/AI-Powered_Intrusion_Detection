import pandas as pd
import numpy as np
import random
import os
import glob

random.seed(0)

drop_columns = [
    # Dataset Specific Information
    "Flow ID",
    "Source IP", "Src IP",
    "Source Port", "Src Port",
    "Destination IP", "Dst IP",
    # Features Without Observed Variance
    "Bwd PSH Flags",
    "Fwd URG Flags",
    "Bwd URG Flags",
    "CWE Flag Count",
    "Fwd Avg Bytes/Bulk", "Fwd Byts/b Avg",
    "Fwd Avg Packets/Bulk", "Fwd Pkts/b Avg",
    "Fwd Avg Bulk Rate", "Fwd Blk Rate Avg",
    "Bwd Avg Bytes/Bulk", "Bwd Byts/b Avg",
    "Bwd Avg Packets/Bulk", "Bwd Pkts/b Avg",
    "Bwd Avg Bulk Rate", "Bwd Blk Rate Avg",
    # Duplicate Column
    'Fwd Header Length.1'
]

mapper = {
    'Dst Port': 'Destination Port',
    'Tot Fwd Pkts': 'Total Fwd Packets',
    'Tot Bwd Pkts': 'Total Backward Packets',
    'TotLen Fwd Pkts': 'Fwd Packets Length Total',
    'Total Length of Fwd Packets': 'Fwd Packets Length Total',
    'TotLen Bwd Pkts': 'Bwd Packets Length Total',
    'Total Length of Bwd Packets': 'Bwd Packets Length Total',
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
    'Fwd Pkts/s': 'Fwd Packets/s',
    'Bwd Pkts/s': 'Bwd Packets/s',
    'Pkt Len Min': 'Packet Length Min',
    'Min Packet Length': 'Packet Length Min',
    'Pkt Len Max': 'Packet Length Max',
    'Max Packet Length': 'Packet Length Max',
    'Pkt Len Mean': 'Packet Length Mean',
    'Pkt Len Std': 'Packet Length Std',
    'Pkt Len Var': 'Packet Length Variance',
    'FIN Flag Cnt': 'FIN Flag Count',
    'SYN Flag Cnt': 'SYN Flag Count',
    'RST Flag Cnt': 'RST Flag Count',
    'PSH Flag Cnt': 'PSH Flag Count',
    'ACK Flag Cnt': 'ACK Flag Count',
    'URG Flag Cnt': 'URG Flag Count',
    'ECE Flag Cnt': 'ECE Flag Count',
    'Pkt Size Avg': 'Avg Packet Size',
    'Average Packet Size': 'Avg Packet Size',
    'Fwd Seg Size Avg': 'Avg Fwd Segment Size',
    'Bwd Seg Size Avg': 'Avg Bwd Segment Size',
    'Fwd Byts/b Avg': 'Fwd Avg Bytes/Bulk',
    'Fwd Pkts/b Avg': 'Fwd Avg Packets/Bulk',
    'Fwd Blk Rate Avg': 'Fwd Avg Bulk Rate',
    'Bwd Byts/b Avg': 'Bwd Avg Bytes/Bulk',
    'Bwd Pkts/b Avg': 'Bwd Avg Packets/Bulk',
    'Bwd Blk Rate Avg': 'Bwd Avg Bulk Rate',
    'Subflow Fwd Pkts': 'Subflow Fwd Packets',
    'Subflow Fwd Byts': 'Subflow Fwd Bytes',
    'Subflow Bwd Pkts': 'Subflow Bwd Packets',
    'Subflow Bwd Byts': 'Subflow Bwd Bytes',
    'Init Fwd Win Byts': 'Init Fwd Win Bytes',
    'Init_Win_bytes_forward': 'Init Fwd Win Bytes',
    'Init Bwd Win Byts': 'Init Bwd Win Bytes',
    'Init_Win_bytes_backward': 'Init Bwd Win Bytes',
    'Fwd Act Data Pkts': 'Fwd Act Data Packets',
    'act_data_pkt_fwd': 'Fwd Act Data Packets',
    'Fwd Seg Size Min': 'Fwd Seg Size Min',
    'min_seg_size_forward': 'Fwd Seg Size Min'
}


def clean_dataset(dataset, filetypes=['feather']):
    # Will search for all files in the dataset subdirectory 'orignal'
    for file in os.listdir(f'{dataset}'):
        print(f"------- {file} -------")
        df = pd.read_csv(f"{dataset}/{file}", skipinitialspace=True, encoding='latin')
        print(df["Label"].value_counts())
        print(f"Shape: {df.shape}")

        # Rename column names for uniform column names across files
        df.rename(columns=mapper, inplace=True)

        # Drop unrelevant columns
        df.drop(columns=drop_columns, inplace=True, errors="ignore")

        print(df.describe())

        # Parse Timestamp column to pandas datetime
        df['Timestamp'] = pd.to_datetime(df['Timestamp'], errors='coerce')
        df['Timestamp'] = df['Timestamp'].apply(lambda x: x + pd.Timedelta(hours=12) if x.hour < 8 else x)
        df = df.sort_values(by=['Timestamp'])

        # Make Label column Categorical
        df['Label'].replace({'BENIGN': 'Benign'}, inplace=True)
        df['Label'] = df.Label.astype('category')

        # Parse Columns to correct dtype
        int_col = df.select_dtypes(include='integer').columns
        df[int_col] = df[int_col].apply(pd.to_numeric, errors='coerce', downcast='integer')
        float_col = df.select_dtypes(include='float').columns
        df[float_col] = df[float_col].apply(pd.to_numeric, errors='coerce', downcast='float')
        obj_col = df.select_dtypes(include='object').columns
        print(f'Columns with dtype == object: {obj_col}')
        df[obj_col] = df[obj_col].apply(pd.to_numeric, errors='coerce')

        # Drop rows with invalid data
        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        print(f"{df.isna().any(axis=1).sum()} invalid rows dropped")
        df.dropna(inplace=True)

        # Drop duplicate rows
        df.drop_duplicates(inplace=True, subset=df.columns.difference(['Label', 'Timestamp']))
        print(df["Label"].value_counts())
        print(f"shape: {df.shape}\n")

        # Reset index
        df.reset_index(inplace=True, drop=True)

        # Plot resulting file
        plot_day(df)

        # Save to file
        if 'feather' in filetypes:
            df.to_feather(f'{dataset}/clean/{file}.feather')
        if 'parquet' in filetypes:
            df.to_parquet(f'{dataset}/clean/{file}.parquet', index=False)


def aggregate_data(dataset, save=True, filetype='feather'):
    # Will search for all files in the 'clean' directory of the correct filetype and aggregate them
    all_data = pd.DataFrame()
    for file in glob.glob(f'{dataset}/clean/*.{filetype}'):
        print(file)
        df = pd.DataFrame()
        if filetype == 'feather':
            df = pd.read_feather(file)
        if filetype == 'parquet':
            df = pd.read_parquet(file)
        print(df.shape)
        print(f'{df["Label"].value_counts()}\n')
        all_data = all_data.append(df, ignore_index=True)
    print('ALL DATA')
    duplicates = all_data[all_data.duplicated(subset=all_data.columns.difference(['Label', 'Timestamp']))]
    print('Removed duplicates after aggregating:')
    print(duplicates.Label.value_counts())
    print('Resulting Dataset')
    all_data.drop(duplicates.index, axis=0, inplace=True)
    all_data.reset_index(inplace=True, drop=True)
    print(all_data.shape)
    print(f'{all_data["Label"].value_counts()}\n')
    if save:
        malicious = all_data[all_data.Label != 'Benign'].reset_index(drop=True)
        benign = all_data[all_data.Label == 'Benign'].reset_index(drop=True)
        if filetype == 'feather':
            all_data.to_feather(f'{dataset}/clean/all_data.feather')
            malicious.to_feather(f'{dataset}/clean/all_malicious.feather')
            benign.to_feather(f'{dataset}/clean/all_benign.feather')
        if filetype == 'parquet':
            all_data.to_parquet(f'{dataset}/clean/all_data.parquet', index=False)
            malicious.to_parquet(f'{dataset}/clean/all_malicious.parquet', index=False)
            benign.to_parquet(f'{dataset}/clean/all_benign.parquet', index=False)


if __name__ == "__main__":
    # Adjust for cleaning the correct dataset into the desired format
    dataset_path = '/Users/avinash/Documents/capstone Project/datasets/MachineLearningCVE'
    # Needs directory with dataset name containing empty dir 'clean' and dir 'original' containing de csv's
    clean_dataset(dataset_path, filetypes=['feather', 'parquet'])
    aggregate_data(dataset_path, save=True, filetype='feather')
    aggregate_data(dataset_path, save=True, filetype='parquet')