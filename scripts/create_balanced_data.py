import os
import gc
import numpy as np
import pandas as pd


# Base project directory
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Data directories
RAW_DATA_DIR = os.path.join(BASE_DIR, "data", "raw")
PROCESSED_DATA_DIR = os.path.join(BASE_DIR, "data", "processed")

# Dataset files
FILES = [
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "Monday-WorkingHours.pcap_ISCX.csv",
    "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    "Tuesday-WorkingHours.pcap_ISCX.csv",
    "Wednesday-workingHours.pcap_ISCX.csv"
]


def create_balanced_csv() -> None:
    """Create a balanced dataset by combining all attack rows and sampling benign rows."""

    sampled_dfs = []

    for file_name in FILES:
        file_path = os.path.join(RAW_DATA_DIR, file_name)

        if not os.path.exists(file_path):
            print(f"!! File Missing: {file_name}")
            continue

        print(f"Processing: {file_name}...")

        try:
            df = pd.read_csv(file_path, skipinitialspace=True, low_memory=False)

            df.columns = df.columns.str.strip()

            benign_mask = df["Label"].str.upper() == "BENIGN"
            benign_df = df[benign_mask]
            attack_df = df[~benign_mask]

            print(f"   -> Found {len(attack_df)} attack rows.")

            benign_sample_size = min(len(benign_df), 40000)

            if benign_sample_size > 0:
                benign_sampled = benign_df.sample(
                    n=benign_sample_size,
                    random_state=42
                )
                combined_chunk = pd.concat([attack_df, benign_sampled])
            else:
                combined_chunk = attack_df

            sampled_dfs.append(combined_chunk)

            del df, benign_df, attack_df
            gc.collect()

        except Exception as e:
            print(f"!! Error processing {file_name}: {e}")

    print("\nMerging all samples into master training set...")
    final_df = pd.concat(sampled_dfs, ignore_index=True)

    final_df.replace([np.inf, -np.inf, "Infinity", "infinity"], np.nan, inplace=True)
    final_df.dropna(inplace=True)

    # Ensure processed directory exists
    os.makedirs(PROCESSED_DATA_DIR, exist_ok=True)

    output_path = os.path.join(PROCESSED_DATA_DIR, "balanced_data.csv")
    final_df.to_csv(output_path, index=False)

    print("\nSUCCESS!")
    print(f"Total rows: {len(final_df)}")
    print(f"Final file: {output_path}")


if __name__ == "__main__":
    create_balanced_csv()