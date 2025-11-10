# train_model.py (updated)
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
import joblib, os

# Create models folder if not exist
os.makedirs("models", exist_ok=True)

# Load dataset
df = pd.read_csv('healthcare-dataset-stroke-data.csv')

# Drop rows with missing values
df = df.dropna()

# Encode categorical columns
le_gender = LabelEncoder()
df['gender'] = le_gender.fit_transform(df['gender'])

le_ever_married = LabelEncoder()
df['ever_married'] = le_ever_married.fit_transform(df['ever_married'])

le_work_type = LabelEncoder()
df['work_type'] = le_work_type.fit_transform(df['work_type'])

le_residence = LabelEncoder()
df['Residence_type'] = le_residence.fit_transform(df['Residence_type'])

le_smoking = LabelEncoder()
df['smoking_status'] = le_smoking.fit_transform(df['smoking_status'])

# Features and target
X = df.drop(columns=['id','stroke'])
y = df['stroke']

# Split data
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train model
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Save model and encoders
joblib.dump(model, 'models/stroke_model.pkl')
joblib.dump(le_gender, 'models/le_gender.pkl')
joblib.dump(le_ever_married, 'models/le_ever_married.pkl')
joblib.dump(le_work_type, 'models/le_work_type.pkl')
joblib.dump(le_residence, 'models/le_residence.pkl')
joblib.dump(le_smoking, 'models/le_smoking.pkl')

print("✅ Model and encoders saved successfully in /models folder!")
