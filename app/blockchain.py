import json, hashlib, random, time
from . import db
from .models import Block

DIFFICULTY = 3

def sha256_hex(s: bytes) -> str:
    return hashlib.sha256(s).hexdigest()

def compute_hash(index, prev_hash, data_json, nonce):
    payload = f"{index}|{prev_hash or ''}|{data_json}|{nonce}".encode()
    return sha256_hex(payload)

def mine_block(index, prev_hash, data_json, difficulty=DIFFICULTY, random_nonce=True, max_iters=10_000_000):
    prefix = '0' * difficulty
    attempts = 0
    if random_nonce:
        while attempts < max_iters:
            nonce = random.randint(0, 1_000_000_000)
            h = compute_hash(index, prev_hash, data_json, nonce)
            if h.startswith(prefix):
                return nonce, h, attempts
            attempts += 1
    else:
        nonce = 0
        while attempts < max_iters:
            h = compute_hash(index, prev_hash, data_json, nonce)
            if h.startswith(prefix):
                return nonce, h, attempts
            nonce += 1
            attempts += 1
    raise RuntimeError("Mining exceeded max iterations")

def get_chain_head():
    last = Block.query.order_by(Block.index.desc()).first()
    return last

def append_block(data: dict, random_nonce=True):
    data_json = json.dumps(data, sort_keys=True)
    head = get_chain_head()
    index = 0 if head is None else head.index + 1
    prev_hash = None if head is None else head.block_hash
    nonce, block_hash, attempts = mine_block(index, prev_hash, data_json, random_nonce=random_nonce)
    blk = Block(index=index, prev_hash=prev_hash, nonce=nonce, data_json=data_json, block_hash=block_hash)
    db.session.add(blk)
    db.session.commit()
    return blk, attempts