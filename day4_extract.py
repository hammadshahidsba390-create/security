
"""
GuardAI — Day 4
Goal: Load CVEFixes.csv, clean it, add language tokens,
      split into train/val/test, save ready for training.
"""

import pandas as pd
import os
from sklearn.model_selection import train_test_split

CSV_PATH = 'Data/CVEFixes.csv'
OUT_DIR  = 'data'
os.makedirs(OUT_DIR, exist_ok=True)

# Focus on top 5 languages — enough data for good training
TARGET_LANGS = ['py', 'js', 'php', 'java', 'go']

LANG_TOKEN = {
    'py':   '[PY]',
    'js':   '[JS]',
    'php':  '[PHP]',
    'java': '[JAVA]',
    'go':   '[GO]',
}

def load_and_filter(path):
    print("[1/5] Loading CSV...")
    df = pd.read_csv(path)
    print(f"      Total loaded: {len(df):,}")

    # Keep only top 5 languages
    df = df[df['language'].isin(TARGET_LANGS)]
    print(f"      After language filter: {len(df):,}")
    return df

def clean(df):
    print("[2/5] Cleaning...")
    before = len(df)

    df = df.dropna(subset=['code'])
    df = df[df['code'].str.strip().str.len() > 30]
    df = df[df['code'].str.len() < 5000]
    df = df.drop_duplicates(subset=['code'])

    print(f"      Removed {before - len(df):,} bad rows")
    print(f"      Clean samples: {len(df):,}")
    return df.reset_index(drop=True)

def prepare(df):
    print("[3/5] Preparing labels and tokens...")

    # Convert safety → label
    df['label'] = df['safety'].map({'vulnerable': 1, 'safe': 0})

    # Add language token to every code sample
    df['input_text'] = df.apply(
        lambda r: f"{LANG_TOKEN.get(r['language'], '[UNK]')} {r['code']}",
        axis=1
    )

    print("      Labels: 1=vulnerable  0=safe")
    print(df.groupby(['language', 'label']).size().unstack(fill_value=0))
    return df

def split(df):
    print("[4/5] Splitting train/val/test...")
    train_l, val_l, test_l = [], [], []

    for lang in TARGET_LANGS:
        sub = df[df['language'] == lang]
        if len(sub) < 10:
            continue
        tr, tmp = train_test_split(
            sub, test_size=0.2,
            stratify=sub['label'], random_state=42
        )
        va, te = train_test_split(
            tmp, test_size=0.5,
            stratify=tmp['label'], random_state=42
        )
        train_l.append(tr)
        val_l.append(va)
        test_l.append(te)
        print(f"      {lang:6s} → train:{len(tr):>5,}  val:{len(va):>4,}  test:{len(te):>4,}")

    return (
        pd.concat(train_l).sample(frac=1, random_state=42),
        pd.concat(val_l).sample(frac=1, random_state=42),
        pd.concat(test_l).sample(frac=1, random_state=42),
    )

def save(train, val, test):
    print("[5/5] Saving...")
    cols = ['input_text', 'label', 'language', 'code']
    train[cols].to_csv(f'{OUT_DIR}/train.csv', index=False)
    val[cols].to_csv(f'{OUT_DIR}/val.csv',     index=False)
    test[cols].to_csv(f'{OUT_DIR}/test.csv',   index=False)
    print(f"      train.csv : {len(train):,}")
    print(f"      val.csv   : {len(val):,}")
    print(f"      test.csv  : {len(test):,}")

def main():
    print("="*50)
    print("  GuardAI — Day 4: Dataset Preparation")
    print("="*50)

    df = load_and_filter(CSV_PATH)
    df = clean(df)
    df = prepare(df)
    train, val, test = split(df)
    save(train, val, test)

    print("\n" + "="*50)
    print("  Day 4 Complete.")
    print(f"  Total training samples : {len(train):,}")
    print(f"  Validation samples     : {len(val):,}")
    print(f"  Test samples           : {len(test):,}")
    print("  Next → run day5_security.py")
    print("="*50)

if __name__ == "__main__":
    main()


