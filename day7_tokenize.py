"""
GuardAI - Day 7
Goal: Load UniXcoder, tokenize dataset,
      verify everything ready for Day 8 training.
"""

import pandas as pd
import torch
from transformers import AutoTokenizer
from torch.utils.data import Dataset

MODEL_NAME = "microsoft/unixcoder-base"
DATA_DIR   = "data"

print("="*50)
print("  GuardAI - Day 7: Tokenization")
print("="*50)

# Step 1: Load tokenizer
print("\n[1/4] Loading UniXcoder tokenizer...")
tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
print(f"      Vocab size : {tokenizer.vocab_size:,}")

# Step 2: Load dataset
print("\n[2/4] Loading dataset...")
train = pd.read_csv(f"{DATA_DIR}/train.csv")
val   = pd.read_csv(f"{DATA_DIR}/val.csv")
test  = pd.read_csv(f"{DATA_DIR}/test.csv")
print(f"      Train : {len(train):,}")
print(f"      Val   : {len(val):,}")
print(f"      Test  : {len(test):,}")

# Step 3: Test tokenization
print("\n[3/4] Testing tokenization...")
sample = train['input_text'].iloc[0]
print(f"      Sample: {sample[:80]}...")

tokens = tokenizer(
    sample,
    max_length=512,
    truncation=True,
    padding='max_length',
    return_tensors='pt'
)
print(f"      Input shape  : {tokens['input_ids'].shape}")
print(f"      Token count  : {tokens['attention_mask'].sum().item()}")

# Step 4: Dataset class
print("\n[4/4] Building PyTorch Dataset...")

class VulnDataset(Dataset):
    def __init__(self, df, tokenizer, max_len=512):
        self.codes  = df['input_text'].tolist()
        self.labels = df['label'].tolist()
        self.tok    = tokenizer
        self.max    = max_len

    def __len__(self):
        return len(self.codes)

    def __getitem__(self, idx):
        enc = self.tok(
            self.codes[idx],
            max_length=self.max,
            truncation=True,
            padding='max_length',
            return_tensors='pt'
        )
        return {
            'input_ids':      enc['input_ids'].squeeze(),
            'attention_mask': enc['attention_mask'].squeeze(),
            'labels':         torch.tensor(
                                  self.labels[idx],
                                  dtype=torch.long
                              )
        }

train_ds = VulnDataset(train, tokenizer)
val_ds   = VulnDataset(val,   tokenizer)
test_ds  = VulnDataset(test,  tokenizer)

# Verify one batch
batch = train_ds[0]
label_name = 'vulnerable' if batch['labels'].item() == 1 else 'safe'
print(f"      First sample shape : {batch['input_ids'].shape}")
print(f"      First sample label : {batch['labels'].item()} ({label_name})")

# GPU check
print("\n--- GPU Check ---")
if torch.cuda.is_available():
    print(f"GPU  : {torch.cuda.get_device_name(0)}")
    print(f"VRAM : {torch.cuda.get_device_properties(0).total_memory/1e9:.1f} GB")
    print("Training will be fast")
else:
    print("No GPU detected — CPU only")
    print("IMPORTANT: Use Google Colab for training (free GPU)")
    print("Go to: colab.research.google.com")
    print("Upload your data/ folder and day8_train.py")

print("\n" + "="*50)
print("  Day 7 Complete.")
print("  Next → Day 8: Fine-tune UniXcoder")
print("="*50)
