import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.metrics import classification_report
import joblib
import os
from transformers import pipeline

# Load the pre-trained question-answering model
qa_pipeline = pipeline("question-answering", model="distilbert-base-uncased-distilled-squad")

CLASSIFIER_MODEL_PATH = "./attack_classifier.joblib"
ANOMALY_MODEL_PATH = "./anomaly_detector.joblib"

def get_qa_pipeline():
    return qa_pipeline

def train_classifier_model():
    # Create a mock dataset for demonstration
    data = {
        'port': [22, 23, 80, 443, 22, 23, 80, 3306, 22, 80, 23, 443, 3306, 80, 22],
        'data_length': [10, 15, 20, 25, 12, 18, 22, 30, 11, 21, 16, 26, 32, 23, 13],
        'keyword_sql': [0, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 1, 1, 0],
        'keyword_ddos': [0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1],
        'keyword_scan': [1, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 1],
        'attack_type': [
            'Port Scan', 'Port Scan', 'SQL Injection', 'Normal', 'Port Scan',
            'Port Scan', 'SQL Injection', 'SQL Injection', 'DDoS', 'SQL Injection',
            'Port Scan', 'Normal', 'SQL Injection', 'Normal', 'DDoS'
        ]
    }
    df = pd.DataFrame(data)

    X = df[['port', 'data_length', 'keyword_sql', 'keyword_ddos', 'keyword_scan']]
    y = df['attack_type']

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    print("Classification Report (Classifier):")
    print(classification_report(y_test, y_pred))

    joblib.dump(model, CLASSIFIER_MODEL_PATH)
    print(f"Classifier model trained and saved to {CLASSIFIER_MODEL_PATH}")
    return model

def load_classifier_model():
    if not os.path.exists(CLASSIFIER_MODEL_PATH):
        print("No classifier model found, training a new one...")
        return train_classifier_model()
    print(f"Loading classifier model from {CLASSIFIER_MODEL_PATH}")
    return joblib.load(CLASSIFIER_MODEL_PATH)

def train_anomaly_model():
    # Use the same mock data for anomaly detection, but without labels
    data = {
        'port': [22, 23, 80, 443, 22, 23, 80, 3306, 22, 80, 23, 443, 3306, 80, 22],
        'data_length': [10, 15, 20, 25, 12, 18, 22, 30, 11, 21, 16, 26, 32, 23, 13],
        'keyword_sql': [0, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 1, 1, 0],
        'keyword_ddos': [0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1],
        'keyword_scan': [1, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 1],
    }
    df = pd.DataFrame(data)

    model = IsolationForest(random_state=42)
    model.fit(df) # Train on the entire dataset to learn normal patterns

    joblib.dump(model, ANOMALY_MODEL_PATH)
    print(f"Anomaly detection model trained and saved to {ANOMALY_MODEL_PATH}")
    return model

def load_anomaly_model():
    if not os.path.exists(ANOMALY_MODEL_PATH):
        print("No anomaly detection model found, training a new one...")
        return train_anomaly_model()
    print(f"Loading anomaly detection model from {ANOMALY_MODEL_PATH}")
    return joblib.load(ANOMALY_MODEL_PATH)

if __name__ == "__main__":
    train_classifier_model()
    train_anomaly_model()