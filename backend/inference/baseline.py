import math
import re

def calculate_entropy(s):
    p, lns = {}, len(s)
    for char in s:
        p[char] = p.get(char, 0) + 1
    return -sum(cnt / lns * math.log2(cnt / lns) for cnt in p.values())

def get_features(domain):
    # Remove TLD (approximate)
    parts = domain.split('.')
    if len(parts) > 1:
        payload = parts[0]
    else:
        payload = domain
        
    length = len(payload)
    digits = len(re.findall(r'\d', payload))
    digit_ratio = digits / length if length > 0 else 0
    entropy = calculate_entropy(payload)
    
    # Vowel ratio (low vowel ratio is suspicious for English-like DGA)
    vowels = len(re.findall(r'[aeiou]', payload))
    vowel_ratio = vowels / length if length > 0 else 0
    
    return {
        "length": length,
        "entropy": entropy,
        "digit_ratio": digit_ratio,
        "vowel_ratio": vowel_ratio
    }

def infer(domain: str):
    """
    Simple heuristic baseline that mimics an ML model.
    High entropy + high digit ratio -> DGA/Malicious
    """
    features = get_features(domain)
    
    # Base score
    score = 0.0
    
    # Feature 1: High Entropy (Randomness)
    # "google" -> ~1.9, "x82j291s" -> ~3.0
    if features["entropy"] > 3.5:
        score += 0.4
    elif features["entropy"] > 2.5:
        score += 0.2
        
    # Feature 2: Length (Very long subdomains are suspicious)
    if features["length"] > 20:
        score += 0.3
    elif features["length"] > 12:
        score += 0.1
        
    # Feature 3: Digit Ratio (Too many numbers)
    if features["digit_ratio"] > 0.3:
        score += 0.3
        
    # Feature 4: Low Vowel Ratio (Unpronounceable)
    if features["vowel_ratio"] < 0.15:
        score += 0.2
        
    # Cap score at 0.99
    score = min(0.99, score)
    
    # Classify
    label = "BENIGN"
    if score > 0.9:
        label = "MALICIOUS"
    elif score > 0.6:
        label = "SUSPICIOUS"
        
    # Add some noise for realism (simulating model uncertainty)
    # In a real model, this would be the probability output
    
    return {
        "label": label,
        "score": round(score, 4),
        "features": features
    }
