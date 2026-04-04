import requests
import pandas as pd
import glob
import time
import random

# Load dataset
all_files = glob.glob(r"D:\PROJECTS\FYRP_IDS\data\raw\*.csv")
df = pd.concat((pd.read_csv(f) for f in all_files), ignore_index=True)

# SAME preprocessing as training
df.columns = df.columns.str.strip()

df.drop(columns=['Flow ID', 'Source IP', 'Destination IP', 'Timestamp'], 
        inplace=True, errors='ignore')

df.replace([float('inf'), float('-inf')], pd.NA, inplace=True)
df.dropna(inplace=True)
nunique = df.nunique()
constant_cols = nunique[nunique == 1].index

print("Removing constant columns:", constant_cols)

df.drop(columns=constant_cols, inplace=True)
X = df.drop('Label', axis=1)

print("🚀 Simulating via API...\n")

for i in range(10):
    idx = random.randint(0, len(X)-1)
    sample = [float(x) for x in X.iloc[idx]]
    response = requests.post(
        "http://127.0.0.1:5000/predict",
        json={"features": sample}
    )

    print(f"\nTraffic {i}")
    print("Status Code:", response.status_code)
    print("Response:", response.text)

    time.sleep(1)