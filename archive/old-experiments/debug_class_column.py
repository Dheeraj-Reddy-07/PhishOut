"""Debug Class column in Phish360 parquet files"""
import pandas as pd

print("=" * 80)
print("Debugging Class Column in Phish360 Parquet")
print("=" * 80)

# Check legit parquet
print("\nPhish360 Legit Parquet:")
legit_df = pd.read_parquet(r"D:\Downloads\phish360_parquet\Phish360_legit.parquet")
print(f"Shape: {legit_df.shape}")
print(f"Columns: {list(legit_df.columns)[:10]}")
print(f"Class column values: {legit_df['Class'].value_counts().to_dict()}")
print(f"Sample Class values: {legit_df['Class'].head().tolist()}")

# Check phish parquet
print("\nPhish360 Phish Parquet:")
phish_df = pd.read_parquet(r"D:\Downloads\phish360_parquet\Phish360_phish.parquet")
print(f"Shape: {phish_df.shape}")
print(f"Columns: {list(phish_df.columns)[:10]}")
print(f"Class column values: {phish_df['Class'].value_counts().to_dict()}")
print(f"Sample Class values: {phish_df['Class'].head().tolist()}")

# Check the split dataframes after shuffling
print("\n" + "=" * 80)
print("After Splitting (from phish360_v3_feature_extractor.py logic)")
print("=" * 80)

RANDOM_SEED = 42
legit_shuffled = legit_df.sample(frac=1, random_state=RANDOM_SEED).reset_index(drop=True)
phish_shuffled = phish_df.sample(frac=1, random_state=RANDOM_SEED).reset_index(drop=True)

legit_train_size = 4660
legit_val_size = 809
legit_test_size = 947

phish_train_size = 3070
phish_val_size = 508
phish_test_size = 754

legit_train = legit_shuffled.iloc[:legit_train_size].copy()
legit_val = legit_shuffled.iloc[legit_train_size:legit_train_size + legit_val_size].copy()
legit_test = legit_shuffled.iloc[legit_train_size + legit_val_size:legit_train_size + legit_val_size + legit_test_size].copy()

phish_train = phish_shuffled.iloc[:phish_train_size].copy()
phish_val = phish_shuffled.iloc[phish_train_size:phish_train_size + phish_val_size].copy()
phish_test = phish_shuffled.iloc[phish_train_size + phish_val_size:phish_train_size + phish_val_size + phish_test_size].copy()

train_df = pd.concat([legit_train, phish_train], ignore_index=True)
val_df = pd.concat([legit_val, phish_val], ignore_index=True)
test_df = pd.concat([legit_test, phish_test], ignore_index=True)

print(f"\nTrain DataFrame Class distribution: {train_df['Class'].value_counts().to_dict()}")
print(f"Val DataFrame Class distribution: {val_df['Class'].value_counts().to_dict()}")
print(f"Test DataFrame Class distribution: {test_df['Class'].value_counts().to_dict()}")
