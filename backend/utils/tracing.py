import uuid
from datetime import datetime

def generate_ray_id():
    return f"RAY-{uuid.uuid4().hex[:8]}"

def current_timestamp():
    return datetime.utcnow().isoformat() + "Z"
