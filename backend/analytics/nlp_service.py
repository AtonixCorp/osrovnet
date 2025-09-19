"""NLP utilities: sentiment analysis and topic modeling.

This provides lightweight wrappers around HuggingFace transformers for sentiment
and gensim for topic modeling. In production, use batching and caching.
"""
from typing import List, Dict


def analyze_sentiment(texts: List[str]) -> List[Dict]:
    """Placeholder sentiment analysis function.

    Replace with a HuggingFace pipeline (e.g., `pipeline('sentiment-analysis')`).
    """
    results = []
    for t in texts:
        results.append({'text': t, 'label': 'NEUTRAL', 'score': 0.5})
    return results


def topic_model(texts: List[str], num_topics: int = 5):
    """Placeholder for topic modeling — use gensim LDA/HDPA or BERTopic.
    """
    # return dummy topics
    return [{'topic_id': i, 'words': ['example', 'topic', str(i)]} for i in range(num_topics)]
