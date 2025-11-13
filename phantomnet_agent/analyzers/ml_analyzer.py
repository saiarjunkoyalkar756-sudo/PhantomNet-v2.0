import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import make_pipeline
from .base import Analyzer
import os

class MLAnalyzer(Analyzer):
    def __init__(self):
        self.model = self._train_model()

    def _train_model(self):
        data_path = os.path.join(os.path.dirname(__file__), '..', 'attack_data.csv')
        df = pd.read_csv(data_path)
        
        model = make_pipeline(TfidfVectorizer(), MultinomialNB())
        model.fit(df['payload'], df['type'])
        return model

    def analyze(self, payload):
        prediction = self.model.predict([payload])
        # Add a confidence score if you want to be more advanced
        # For now, just return the predicted type
        return prediction[0]
