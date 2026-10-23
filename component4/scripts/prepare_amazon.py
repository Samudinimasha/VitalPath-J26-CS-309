
from pathlib import Path
import pandas as pd

ROOT = Path(__file__).resolve().parent.parent

source = ROOT / "datasets/raw/amazon_access_sample.csv"
output = ROOT / "datasets/processed/amazon_access_processed.csv"

df = pd.read_csv(source)

required = [
    "ACTION",
    "TARGET_NAME",
    "LOGIN",
    "REQUEST_DATE",
    "AUTHORIZATION_DATE",
]

missing = [c for c in required if c not in df.columns]

if missing:
    raise ValueError(f"Missing columns: {missing}")

df["REQUEST_DATE"] = pd.to_datetime(
    df["REQUEST_DATE"], errors="coerce"
)

df["AUTHORIZATION_DATE"] = pd.to_datetime(
    df["AUTHORIZATION_DATE"], errors="coerce"
)

df["authorization_delay_minutes"] = (
    df["AUTHORIZATION_DATE"] - df["REQUEST_DATE"]
).dt.total_seconds() / 60

df["action_category"] = df["ACTION"].str.lower().str.strip()

df["user_resource_changes"] = (
    df.groupby(["LOGIN", "TARGET_NAME"])["ACTION"]
    .transform("size")
)

output.parent.mkdir(parents=True, exist_ok=True)
df.to_csv(output, index=False)

print("Total records:", len(df))
print("Unique users:", df["LOGIN"].nunique())
print("Unique resources:", df["TARGET_NAME"].nunique())

print("\nAccess action counts:")
print(df["action_category"].value_counts())

print("\nAuthorization delay statistics (minutes):")
print(df["authorization_delay_minutes"].describe())

print("\nProcessed dataset saved to:")
print(output)
