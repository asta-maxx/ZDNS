import joblib
import os
import sys
import math
from pathlib import Path

# Fallback
from backend.inference.baseline import infer as heuristic_infer

# Path setup
BASE_DIR = Path(__file__).resolve().parent.parent.parent
MODEL_PATH = BASE_DIR / "backend" / "models" / "best_naive_bayes_model.pkl"

MODEL = None
OFFSET_BIAS = 0.0  # Adjust if model is too sensitive

def load_model():
    global MODEL
    if MODEL is None:
        try:
            if MODEL_PATH.exists():
                print(f"Loading model from {MODEL_PATH}...")
                MODEL = joblib.load(MODEL_PATH)
                print("Model loaded successfully.")
            else:
                print(f"Model not found at {MODEL_PATH}. Using heuristic baseline.")
        except Exception as e:
            print(f"Failed to load model: {e}")
            MODEL = None

class ModelWrapper:
    """Wrapper to handle model inference safely"""
    
    @staticmethod
    def infer(domain: str):
        # Ensure model is loaded (lazy load attempt)
        if MODEL is None:
            load_model()
            
        # If still None, fallback
        if MODEL is None:
            result = heuristic_infer(domain)
            result["source"] = "heuristic"
            return result

        try:
            # Predict
            # Naive Bayes usually outputs [prob_benign, prob_malicious]
            # Assming classes are [0, 1] or ['benign', 'dga']
            
            # We try passing the domain as a list [domain]
            # This works if the model is a Pipeline(Vectorizer -> Classifier)
            
            # Check classes_ if possible to know which is malicious
            malicious_index = 1
            if hasattr(MODEL, "classes_"):
                # If classes are strings, find the "malicious" / "dga" one
                # Common names: "dga", "malware", "1", 1
                classes = MODEL.classes_
                for i, cls in enumerate(classes):
                    if str(cls).lower() in ["dga", "malicious", "malware", "1"]:
                        malicious_index = i
                        break
            
            probs = MODEL.predict_proba([domain])[0]
            score = float(probs[malicious_index])
            
            # Determine label
            label = "BENIGN"
            if score > 0.9:
                label = "MALICIOUS"
            elif score > 0.6:
                label = "SUSPICIOUS"
            
            return {
                "label": label,
                "score": round(score, 4),
                "features": {"model": "Naive Bayes", "raw_score": score},
                "source": "model"
            }

        except Exception as e:
            print(f"Inference error: {e}. Falling back to heuristic.")
            # Fallback
            result = heuristic_infer(domain)
            result["source"] = "heuristic_fallback"
            return result

# Expose the infer function directly
def infer(domain: str):
    return ModelWrapper.infer(domain)

def get_status():
    return {
        "loaded": MODEL is not None,
        "fallback_active": MODEL is None,
        "model_path": str(MODEL_PATH),
        "model_version": "nb_v1.0"
    }

# Pre-load on import
load_model()
