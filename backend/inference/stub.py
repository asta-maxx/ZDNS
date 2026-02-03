def infer(domain: str):
    if any(char.isdigit() for char in domain):
        return {"label": "DGA", "score": 0.95}
    return {"label": "BENIGN", "score": 0.05}
