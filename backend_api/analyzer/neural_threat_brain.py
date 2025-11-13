from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import SGDClassifier
from sklearn.pipeline import make_pipeline
import numpy as np

# Mock training data
X_train = [
    "GET /etc/passwd",
    "SELECT * FROM users",
    "<script>alert('XSS')</script>",
    " عادي",
]
y_train = ["command_injection", "sql_injection", "xss", "normal"]

class NeuralThreatBrain:
    def __init__(self):
        self.model = make_pipeline(TfidfVectorizer(), SGDClassifier(loss='log_loss'))
        self.model.fit(X_train, y_train)

    def predict(self, data: str) -> tuple[str, float]:
        """
        Predicts the attack type and confidence score for the given data.
        """
        prediction = self.model.predict([data])[0]
        confidence = np.max(self.model.predict_proba([data]))
        return prediction, confidence

    def retrain(self, new_data: list[str], new_labels: list[str]):
        """
        Retrains the model with new data.
        """
        self.model.fit(new_data, new_labels)

brain = NeuralThreatBrain()