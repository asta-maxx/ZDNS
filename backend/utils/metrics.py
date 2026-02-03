metrics = {
    "total_queries": 0,
    "blocked": 0,
    "warnings": 0,
    "allowed": 0
}

def inc(key):
    metrics[key] += 1

def get_metrics():
    return metrics
