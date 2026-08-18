#!/usr/bin/env python3
import hashlib, json, signal, time, zlib
from dataclasses import dataclass, asdict
from pathlib import Path
from blake3 import blake3

NETWORKS = {
    "TESTNET": {
        "name": "GODCHAIN-TESTNET",
        "version": "4.0-testnet",
        "difficulty": 3,
        "block_reward": 50,
        "block_interval": 5,
        "chain_file": Path("data/testnet/godchain.json"),
    },
    "MAINNET": {
        "name": "GODCHAIN-MAINNET",
        "version": "4.0-mainnet",
        "difficulty": 5,
        "block_reward": 50,
        "block_interval": 10,
        "chain_file": Path("data/mainnet/godchain.json"),
    },
}

# Local-only profile. This does not connect to any existing cryptocurrency network.
NETWORK_MODE = "TESTNET"
CONFIG = NETWORKS[NETWORK_MODE]
NETWORK = CONFIG["name"]
VERSION = CONFIG["version"]
DIFFICULTY = CONFIG["difficulty"]
BLOCK_REWARD = CONFIG["block_reward"]
BLOCK_INTERVAL = CONFIG["block_interval"]
CHAIN_FILE = CONFIG["chain_file"]
PBKDF2_ITERATIONS = 2048
JOATT_SALT = b"JOATT-SALT-TEST-ONLY"
RUNNING = True


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def sha256(data):
    return hashlib.sha256(data).digest()


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def blake3_256(data):
    return blake3(data).digest(length=32)


def tiger128_test(data):
    return sha256(b"TIGER128|TEST-ONLY|" + data)[:16]


def haval192_test(data):
    return sha256(b"HAVAL192|TEST-ONLY|" + data)[:24]


def joatt(payload, previous_state):
    blake3_state = blake3_256(
        b"JOATT-BLAKE3-EVOLUTION|" +
        NETWORK.encode() + b"|" +
        previous_state + b"|" + payload
    )

    root = sha256(
        b"JOATT|" + NETWORK.encode() + b"|" +
        previous_state + b"|" + blake3_state + b"|" + payload
    )

    pbkdf = hashlib.pbkdf2_hmac(
        "sha512", root, JOATT_SALT,
        PBKDF2_ITERATIONS, 64
    )

    tiger = tiger128_test(pbkdf)
    haval = haval192_test(tiger + pbkdf)
    adler = zlib.adler32(haval) & 0xffffffff

    identifier64 = sha256(
        b"JOATT-ID64|" + blake3_state +
        previous_state + tiger + haval +
        adler.to_bytes(4, "big")
    )[:8]

    state256 = sha256(
        b"JOATT-STATE256|" + blake3_state +
        previous_state + root + pbkdf +
        tiger + haval + identifier64
    )

    return {
        "algorithm": "JOATT-BLAKE3-EVOLVED-TEST",
        "blake3_state256": blake3_state.hex(),
        "root_sha256": root.hex(),
        "pbkdf2_hmac_sha512": pbkdf.hex(),
        "tiger128_test": tiger.hex(),
        "haval192_test": haval.hex(),
        "adler32": f"{adler:08x}",
        "identifier64": identifier64.hex(),
        "state256": state256.hex(),
    }


def validate_joatt(result):
    lengths = {
        "blake3_state256": 64,
        "root_sha256": 64,
        "pbkdf2_hmac_sha512": 128,
        "tiger128_test": 32,
        "haval192_test": 48,
        "adler32": 8,
        "identifier64": 16,
        "state256": 64,
    }
    try:
        return all(
            len(result[k]) == n and int(result[k], 16) >= 0
            for k, n in lengths.items()
        )
    except (KeyError, ValueError, TypeError):
        return False


@dataclass
class Block:
    index: int
    timestamp: float
    previous_hash: str
    transactions: list
    joatt_identifier: str
    joatt_state: str
    nonce: int = 0
    hash: str = ""

    def header(self):
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "previous_hash": self.previous_hash,
            "transactions": self.transactions,
            "joatt_identifier": self.joatt_identifier,
            "joatt_state": self.joatt_state,
            "nonce": self.nonce,
        }

    def calculate_hash(self):
        return sha256_hex(canonical(self.header()))

    def mine(self):
        target = "0" * DIFFICULTY
        while RUNNING:
            self.hash = self.calculate_hash()
            if self.hash.startswith(target):
                return True
            self.nonce += 1
        return False


class GodChain:
    def __init__(self):
        self.chain = []
        self.pending = []
        CHAIN_FILE.parent.mkdir(parents=True, exist_ok=True)

        if CHAIN_FILE.exists():
            try:
                self.load()
                if not self.validate():
                    raise RuntimeError("Stored chain failed validation")
                print(f"[CHAIN] Loaded {NETWORK}")
            except Exception as error:
                print(f"[CHAIN] Invalid state: {error}")
                self.chain = []
                self.create_genesis()
        else:
            self.create_genesis()

    @property
    def latest(self):
        return self.chain[-1]

    def create_genesis(self):
        transactions = [{
            "type": "GENESIS",
            "network": NETWORK,
            "version": VERSION,
            "message": "GODCHAIN GENESIS",
            "vector": "1011",
        }]

        result = joatt(canonical(transactions), b"\x00" * 32)

        if not validate_joatt(result):
            raise RuntimeError("Genesis JOATT validation failed")

        block = Block(
            0, 0, "0" * 64, transactions,
            result["identifier64"], result["state256"]
        )
        block.hash = block.calculate_hash()
        self.chain = [block]
        self.save()

    def add_transaction(self, sender, recipient, amount):
        if amount <= 0:
            raise ValueError("Amount must be positive")
        tx = {
            "sender": sender,
            "recipient": recipient,
            "amount": amount,
            "timestamp": time.time(),
        }
        self.pending.append(tx)
        return tx

    def evolve_state(self, transactions):
        previous_state = bytes.fromhex(self.latest.joatt_state)
        payload = canonical({
            "height": len(self.chain),
            "previous_hash": self.latest.hash,
            "transactions": transactions,
            "network": NETWORK,
        })
        result = joatt(payload, previous_state)
        if not validate_joatt(result):
            raise RuntimeError("JOATT state validation failed")
        return result

    def mine_block(self):
        transactions = list(self.pending)
        transactions.append({
            "type": "MINING_REWARD",
            "sender": NETWORK,
            "recipient": "GOD_MINER",
            "amount": BLOCK_REWARD,
            "timestamp": time.time(),
        })

        result = self.evolve_state(transactions)

        block = Block(
            len(self.chain), time.time(), self.latest.hash,
            transactions, result["identifier64"], result["state256"]
        )

        print(f"[MINING] {NETWORK} block={block.index}")
        print(f"[BLAKE3] {result['blake3_state256']}")

        started = time.time()
        if not block.mine():
            return False

        elapsed = time.time() - started
        self.chain.append(block)
        self.pending.clear()

        print(f"[BLOCK] index={block.index} nonce={block.nonce} time={elapsed:.3f}s")
        print(f"[HASH] {block.hash}")
        print(f"[JOATT-ID64] {block.joatt_identifier}")
        print(f"[JOATT-STATE256] {block.joatt_state}")
        return True

    def validate(self):
        if not self.chain:
            return False

        genesis = self.chain[0]
        if genesis.previous_hash != "0" * 64:
            return False
        if genesis.hash != genesis.calculate_hash():
            return False

        for current, previous in zip(self.chain[1:], self.chain):
            if current.hash != current.calculate_hash():
                return False
            if current.previous_hash != previous.hash:
                return False
            if not current.hash.startswith("0" * DIFFICULTY):
                return False
            if len(current.joatt_state) != 64:
                return False
            if len(current.joatt_identifier) != 16:
                return False
        return True

    def balance(self, address):
        balance = 0
        for block in self.chain:
            for tx in block.transactions:
                if tx.get("sender") == address:
                    balance -= tx["amount"]
                if tx.get("recipient") == address:
                    balance += tx["amount"]
        return balance

    def save(self):
        data = {
            "name": "GODCHAIN",
            "network": NETWORK,
            "version": VERSION,
            "difficulty": DIFFICULTY,
            "block_reward": BLOCK_REWARD,
            "chain": [asdict(block) for block in self.chain],
        }
        tmp = CHAIN_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2))
        tmp.replace(CHAIN_FILE)

    def load(self):
        data = json.loads(CHAIN_FILE.read_text())
        if data.get("network") != NETWORK:
            raise RuntimeError("Network mismatch")
        self.chain = [Block(**block) for block in data["chain"]]


def shutdown(signum, frame):
    global RUNNING
    print("\n[SHUTDOWN] Requested.")
    RUNNING = False


signal.signal(signal.SIGINT, shutdown)
signal.signal(signal.SIGTERM, shutdown)


def automate():
    chain = GodChain()

    print("=" * 68)
    print("GODCHAIN / JOATT / BLAKE3")
    print("=" * 68)
    print(f"MODE       : {NETWORK_MODE}")
    print(f"NETWORK    : {NETWORK}")
    print(f"VERSION    : {VERSION}")
    print(f"DIFFICULTY : {DIFFICULTY}")
    print(f"REWARD     : {BLOCK_REWARD}")
    print(f"INTERVAL   : {BLOCK_INTERVAL}s")
    print(f"CHAIN      : {CHAIN_FILE}")
    print("=" * 68)

    while RUNNING:
        try:
            if not chain.validate():
                raise RuntimeError("CHAIN VALIDATION FAILED")

            print(f"[VALID] height={len(chain.chain) - 1}")

            chain.mine_block()

            if not chain.validate():
                raise RuntimeError("POST-MINING VALIDATION FAILED")

            chain.save()
            print(f"[SAVE] {CHAIN_FILE}")

            for _ in range(BLOCK_INTERVAL):
                if not RUNNING:
                    break
                time.sleep(1)

        except Exception as error:
            print(f"[ERROR] {error}")
            time.sleep(5)

    chain.save()
    print("[GODCHAIN] Stopped safely.")


if __name__ == "__main__":
    automate()
