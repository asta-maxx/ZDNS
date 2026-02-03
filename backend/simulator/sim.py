import requests, random, time

domains = [
    "google.com",
    "openai.com",
    "xk92jd92.biz",
    "abc123xyz.ru"
]

while True:
    d = random.choice(domains)
    res = requests.post(
        "http://127.0.0.1:8000/dns/query",
        json={"domain": d}
    )
    print(d, res.json())
    time.sleep(1)
