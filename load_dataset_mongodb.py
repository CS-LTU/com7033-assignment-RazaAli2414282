import pandas as pd
from pymongo import MongoClient
from datetime import datetime

# Connect to MongoDB
client = MongoClient("mongodb://localhost:27017/")
db = client["stroke_app"]
patients_collection = db["patients"]

# Load CSV
df = pd.read_csv("healthcare-dataset-stroke-data.csv")  # place CSV in project root

# Drop rows with missing values
df = df.dropna()

# Convert each row to dictionary
records = []
for _, row in df.iterrows():
    record = row.to_dict()
    record["created_at"] = datetime.utcnow()
    records.append(record)

# Insert into MongoDB
patients_collection.insert_many(records)
print(f"{len(records)} records inserted into MongoDB successfully!")
