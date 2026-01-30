import hashlib, random, time, json, argparse, sys

def compute_hash(index, prev_hash, data_json, nonce):
    payload = f"{index}|{prev_hash}|{data_json}|{nonce}".encode()
    return hashlib.sha256(payload).hexdigest()

def p_o_w_random(data, difficulty=3, attempts=100000):
    prefix = "0" * difficulty
    for i in range(attempts):
        nonce = random.randint(0, 99999999)
        h = compute_hash(0, "", data, nonce)
        if h.startswith(prefix):
            return {
                "nonce": nonce,
                "hash": h,
                "attempts": i + 1,
                "method": "Random Search"
            }
    return None

def p_o_w_incremental(data, difficulty=3, attempts=100000):
    prefix = "0" * difficulty
    nonce = 0
    for i in range(attempts):
        h = compute_hash(0, "", data, nonce)
        if h.startswith(prefix):
            return {
                "nonce": nonce,
                "hash": h,
                "attempts": i + 1,
                "method": "Incremental Search"
            }
        nonce += 1
    return None

def pow_benchmark(data, difficulty=3):
    # Random nonce method
    t1 = time.time()
    r1 = p_o_w_random(data, difficulty)
    t2 = time.time()

    # Incremental nonce method
    t3 = time.time()
    r2 = p_o_w_incremental(data, difficulty)
    t4 = time.time()

    return {
        "difficulty": difficulty,
        "random_search": {
            "result": r1,
            "time_ms": int((t2 - t1) * 1000)
        },
        "incremental_search": {
            "result": r2,
            "time_ms": int((t4 - t3) * 1000)
        }
    }

# ------------------------
# JSON Output Support
# ------------------------
def benchmark_json():
    result = pow_benchmark("test-data", difficulty=3)
    # Extract simplified format for dashboard
    out = {
        "random_ms": result["random_search"]["time_ms"],
        "increment_ms": result["incremental_search"]["time_ms"]
    }
    print(json.dumps(out))
    return out

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true", help="Output benchmark in JSON format")
    args = parser.parse_args()

    if args.json:
        benchmark_json()
    else:
        # Normal console output
        print(pow_benchmark("test-data", difficulty=3))
