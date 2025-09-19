"""Predictive analytics helpers: forecasting utilities and model wrappers.

This module provides small helper functions using statsmodels and TensorFlow/Keras
for time-series forecasting. It's intentionally lightweight — production pipelines
should move to a dedicated analytics service or notebook workflow.
"""
from typing import List, Dict, Any
import numpy as np
import pandas as pd


def simple_moving_average_forecast(series: List[float], window: int = 3, steps: int = 10) -> List[float]:
    s = pd.Series(series)
    last = s.rolling(window=window).mean().iloc[-1]
    # naive forecast: repeat last rolling mean
    return [float(last)] * steps


def prepare_ts(series: List[float]):
    return pd.Series(series)
