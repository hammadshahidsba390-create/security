import pandas as pd
import numpy as np
import os

if not os.path.exists('data/test.csv'):
    print("❌ Error: data/test.csv not found.")
    exit(1)

print("Reading real evaluation dataset...")
df = pd.read_csv('data/test.csv', low_memory=False)
df.columns = df.columns.str.strip()

# Uniform header adjustments to match app parser
df.rename(columns={
    'Flow Byts/s': 'Flow Bytes/s',
    'Flow Pkts/s': 'Flow Packets/s'
}, inplace=True)

df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.fillna(0, inplace=True)

# Smart column lookup for target labels
target_col = None
possible_cols = ['Label', 'label', 'Class', 'class', 'Threat']

for col in possible_cols:
    if col in df.columns:
        target_col = col
        break

if target_col is None:
    print("❌ Error: Could not find a target classification column.")
    print(f"Available columns in your file are:\n{list(df.columns)}")
    exit(1)

# Ensure the column name is standard inside the output file
if target_col != 'Label':
    df.rename(columns={target_col: 'Label'}, inplace=True)

print(f"✅ Found target data column: '{target_col}'")
print("\n--- Available Labels in Test Set ---")
print(df['Label'].value_counts())
print("------------------------------------\n")

# Slice out accurate traffic distributions
benign  = df[df['Label'] == 'Benign'].head(100)
attacks = df[df['Label'] != 'Benign'].head(300)

if len(attacks) == 0:
    print("⚠️ Warning: No explicit 'Benign' labels found. Grabbing top 400 rows instead.")
    test_df = df.head(400).sample(frac=1, random_state=42)
else:
    test_df = pd.concat([benign, attacks]).sample(frac=1, random_state=42)

test_df.to_csv('data/guardai_real_test.csv', index=False)
print(f"✅ Success! Saved {len(test_df)} authentic rows to data/guardai_real_test.csv")
