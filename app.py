"""
SecurePass Analyzer - CAP790 CA3 project
Multi-layer password assessment with privacy-preserving breach detection.
Run:  python app.py   ->  open http://127.0.0.1:5000
"""
import hashlib
import math
import re
import secrets
import string
import time

import bcrypt
import requests
from flask import Flask, jsonify, render_template, request
from zxcvbn import zxcvbn

app = Flask(__name__)
HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/"

WORDS = """acid anchor apple arrow basket beacon bridge candle canyon carbon castle cedar
circuit cobalt comet copper coral crystal dagger delta desert diamond dragon eagle ember
engine falcon feather forest fossil galaxy garden glacier granite harbor hazel horizon
island jacket jungle kernel lantern lemon lizard magnet marble meadow mirror monsoon
mountain nebula needle ocean orchid oyster panda pepper pillar planet pocket prism
pylon quartz rabbit radar river rocket saddle shadow signal silver spiral summit tablet
thunder tiger timber tunnel turbine umbrella valley velvet violet voyage walnut whisper
window winter wizard yellow zephyr zigzag anvil badge bronze cactus drift fable gecko
haven ivory jolt koala lotus mango noble olive plume quill raven sprout topaz urchin""".split()


# ---------- Layer 1: entropy ----------
def charset_size(pw):
    size = 0
    if re.search(r"[a-z]", pw): size += 26
    if re.search(r"[A-Z]", pw): size += 26
    if re.search(r"\d", pw): size += 10
    if re.search(r"[^A-Za-z0-9]", pw): size += 32
    return size


def entropy_bits(pw):
    n = charset_size(pw)
    return round(len(pw) * math.log2(n), 1) if n else 0.0


# ---------- Layer 3: crack-time formatting ----------
def human_time(seconds):
    if seconds < 1:
        return "instantly"
    units = [("year", 31536000), ("month", 2592000), ("day", 86400),
             ("hour", 3600), ("minute", 60), ("second", 1)]
    if seconds >= 31536000 * 1e9:
        return "billions of years+"
    for name, size in units:
        if seconds >= size:
            v = int(seconds // size)
            return f"{v:,} {name}{'s' if v != 1 else ''}"
    return "instantly"


# ---------- Layer 4: k-anonymity breach check ----------
def breach_check(pw):
    sha1 = hashlib.sha1(pw.encode("utf-8")).hexdigest().upper()  # hashed locally
    prefix, suffix = sha1[:5], sha1[5:]                          # only prefix leaves
    try:
        r = requests.get(HIBP_RANGE_URL + prefix,
                         headers={"Add-Padding": "true"}, timeout=8)
        r.raise_for_status()
    except requests.RequestException:
        return {"checked": False, "prefix": prefix,
                "error": "Could not reach the breach database (check internet)."}
    count = 0
    for line in r.text.splitlines():
        h, _, c = line.partition(":")
        if h == suffix:          # match is done locally
            count = int(c)
            break
    return {"checked": True, "prefix": prefix, "breached": count > 0, "count": count,
            "returned": len(r.text.splitlines())}


@app.route("/")
def index():
    return render_template("index.html")


@app.post("/api/analyze")
def analyze():
    pw = (request.get_json(silent=True) or {}).get("password", "")
    if not pw:
        return jsonify(error="Enter a password first."), 400
    pw = pw[:72]  # zxcvbn/bcrypt limit; also keeps analysis fast

    res = zxcvbn(pw)                                        # Layer 2: patterns + dictionary
    ct = res["crack_times_seconds"]                         # Layer 3: crack time
    scenarios = [
        ("Online attack, throttled (100 guesses/hour)", ct["online_throttling_100_per_hour"]),
        ("Online attack, no throttling (10 guesses/sec)", ct["online_no_throttling_10_per_second"]),
        ("Offline, slow hash like bcrypt (10,000/sec)", ct["offline_slow_hashing_1e4_per_second"]),
        ("Offline, fast hash like MD5/SHA-1 (10 billion/sec)", ct["offline_fast_hashing_1e10_per_second"]),
    ]
    patterns = sorted({s["pattern"] for s in res["sequence"]})
    breach = breach_check(pw)                               # Layer 4

    score = res["score"]  # 0..4
    if breach.get("breached"):
        score = 0         # a leaked password is never safe, whatever its complexity

    tips = list(res["feedback"].get("suggestions", []))
    if res["feedback"].get("warning"):
        tips.insert(0, res["feedback"]["warning"])
    if len(pw) < 12:
        tips.append("Use at least 12 characters; length matters more than symbols.")
    if breach.get("breached"):
        tips.insert(0, "This password appears in known data breaches. Never use it again.")
    if "dictionary" in patterns:
        tips.append("Avoid dictionary words, even with substitutions like @ for a.")

    return jsonify(score=score, entropy=entropy_bits(pw), length=len(pw),
                   charset=charset_size(pw), guesses=res["guesses"],
                   scenarios=[{"name": n, "time": human_time(t), "seconds": float(t)} for n, t in scenarios],
                   patterns=patterns, breach=breach, tips=tips)


@app.post("/api/hash-demo")
def hash_demo():
    pw = (request.get_json(silent=True) or {}).get("password", "")
    if not pw:
        return jsonify(error="Enter a password first."), 400
    pw = pw[:72]
    t0 = time.perf_counter()
    salted = bcrypt.hashpw(pw.encode(), bcrypt.gensalt(rounds=12)).decode()
    bcrypt_ms = round((time.perf_counter() - t0) * 1000)
    return jsonify(
        plain=pw,
        md5=hashlib.md5(pw.encode()).hexdigest(),
        sha256=hashlib.sha256(pw.encode()).hexdigest(),
        bcrypt=salted, bcrypt_ms=bcrypt_ms,
        bcrypt_again=bcrypt.hashpw(pw.encode(), bcrypt.gensalt(rounds=12)).decode())


@app.get("/api/generate")
def generate():
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    password = "".join(secrets.choice(alphabet) for _ in range(16))
    phrase = "-".join(secrets.choice(WORDS) for _ in range(6))
    return jsonify(password=password, passphrase=phrase,
                   passphrase_bits=round(6 * math.log2(len(WORDS)), 1))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
