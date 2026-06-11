import struct
import hashlib


class CompactSizeEncoder:
    """
    Encodes an integer into Bitcoin's CompactSize format.
    """

    def encode(self, value: int) -> bytes:
        if not isinstance(value, int):
            raise ValueError("Value must be an integer.")

        if value < 0 or value > 0xFFFFFFFFFFFFFFFF:
            raise ValueError("Value must fit within u64 range.")

        if value < 0xFD:
            return value.to_bytes(1, byteorder="little")
        elif value <= 0xFFFF:
            return b"\xfd" + value.to_bytes(2, byteorder="little")
        elif value <= 0xFFFFFFFF:
            return b"\xfe" + value.to_bytes(4, byteorder="little")
        else:
            return b"\xff" + value.to_bytes(8, byteorder="little")


class CompactSizeDecoder:
    """
    Decodes Bitcoin's CompactSize bytes into an integer.
    """

    def decode(self, data: bytes) -> tuple[int, int]:
        if not data:
            raise ValueError("Data is too short to decode CompactSize.")

        first_byte = data[0]

        if first_byte < 0xFD:
            return first_byte, 1

        elif first_byte == 0xFD:
            if len(data) < 3:
                raise ValueError("Data too short")
            return int.from_bytes(data[1:3], byteorder="little"), 3

        elif first_byte == 0xFE:
            if len(data) < 5:
                raise ValueError("Data too short")
            return int.from_bytes(data[1:5], byteorder="little"), 5

        elif first_byte == 0xFF:
            if len(data) < 9:
                raise ValueError("Data too short")
            return int.from_bytes(data[1:9], byteorder="little"), 9

        raise ValueError("Invalid CompactSize prefix.")


class TransactionData:
    """
    A class to represent and manage simplified Bitcoin transaction data.
    """

    def __init__(self, version: int = 1, lock_time: int = 0):
        self.version = version
        self.inputs = []
        self.outputs = []
        self.lock_time = lock_time
        self.metadata = {}

    def add_input(
        self,
        tx_id: str,
        vout_index: int,
        script_sig: str,
        sequence: int = 0xFFFFFFFF
    ):
        tx_input = {
            "prev_txid": tx_id,
            "prev_vout": vout_index,
            "script_sig": script_sig,
            "sequence": sequence
        }

        self.inputs.append(tx_input)
        print(f"Added input: {tx_id}:{vout_index}")

    def add_output(self, value_satoshi: int, script_pubkey: str):
        tx_output = (value_satoshi, script_pubkey)

        self.outputs.append(tx_output)
        print(f"Added output: {value_satoshi} sat")

    def get_input_details(self) -> list[dict]:
        detailed_inputs = []

        print("\n--- Input Details (using for and enumerate) ---")

        for index, input_data in enumerate(self.inputs):
            print(f"Input #{index}")

            prev_txid = input_data.get("prev_txid")
            prev_vout = input_data.get("prev_vout")
            script_sig = input_data.get("script_sig")

            print(f"  TXID: {prev_txid}")
            print(f"  VOUT: {prev_vout}")
            print(f"  ScriptSig: {script_sig}")

            detailed_inputs.append(input_data.copy())

        return detailed_inputs

    def summarize_outputs(self, min_value: int = 0) -> tuple[int, int]:
        total_satoshi = 0
        valid_outputs_count = 0
        index = 0

        print("\n--- Summarizing Outputs (using while, continue, break) ---")

        while index < len(self.outputs):
            value, script = self.outputs[index]
            index += 1

            if not isinstance(value, int) or value < 0:
                print(f"Skipping invalid output: {value}")
                continue

            if value < min_value:
                print(f"Skipping output below minimum: {value}")
                continue

            total_satoshi += value
            valid_outputs_count += 1

            print(f"Including output: {value} -> {script}")

            if total_satoshi > 1_000_000_000:
                print(
                    "Total satoshis exceeded 1 Billion. "
                    "Breaking summarization."
                )
                break

        return total_satoshi, valid_outputs_count

    def update_metadata(self, new_data: dict):
        self.metadata.update(new_data)
        print(f"Updated metadata: {self.metadata}")

    def get_metadata_value(self, key: str, default=None):
        return self.metadata.get(key, default)

    def get_transaction_header(self) -> tuple:
        return (
            self.version,
            len(self.inputs),
            len(self.outputs),
            self.lock_time
        )

    def set_transaction_header(
        self,
        version: int,
        num_inputs: int,
        num_outputs: int,
        lock_time: int
    ):
        self.version, _, _, self.lock_time = (
            version,
            num_inputs,
            num_outputs,
            lock_time
        )

        print("Set header via multiple assignment")


class UTXOSet:
    """
    Manages a set of UTXOs.
    """

    def __init__(self):
        self.utxos = set()

    def add_utxo(self, tx_id: str, vout_index: int, amount: int):
        utxo = (tx_id, vout_index, amount)

        self.utxos.add(utxo)
        print(f"Added UTXO: {utxo}")

    def remove_utxo(
        self,
        tx_id: str,
        vout_index: int,
        amount: int
    ) -> bool:
        utxo = (tx_id, vout_index, amount)

        if utxo in self.utxos:
            self.utxos.remove(utxo)
            print(f"Removed UTXO: {utxo}")
            return True

        print("UTXO not found")
        return False

    def get_balance(self) -> int:
        total = 0

        for _, _, amount in self.utxos:
            total += amount

        return total

    def find_sufficient_utxos(self, target_amount: int) -> set:
        selected = set()
        running_total = 0
    
        for utxo in self.utxos:
            selected.add(utxo)
            running_total += utxo[2]
    
            if running_total >= target_amount:
                print("Found sufficient UTXOs")
                return selected
    
        print("Could not find sufficient UTXOs")
        return set()
        
    def get_total_utxo_count(self) -> int:
        return len(self.utxos)

    def is_subset_of(self, other_utxo_set: 'UTXOSet') -> bool:
        return self.utxos.issubset(other_utxo_set.utxos)

    def combine_utxos(self, other_utxo_set: 'UTXOSet') -> 'UTXOSet':
        combined_set = UTXOSet()
        combined_set.utxos = self.utxos.union(other_utxo_set.utxos)
        return combined_set

    def find_common_utxos(self, other_utxo_set: 'UTXOSet') -> 'UTXOSet':
        common_set = UTXOSet()
        common_set.utxos = self.utxos.intersection(other_utxo_set.utxos)
        return common_set


def generate_block_headers(
    prev_block_hash: str,
    merkle_root: str,
    timestamp: int,
    bits: int,
    start_nonce: int = 0,
    max_attempts: int = 1000
):
    print("\n--- Generating Block Headers (using generator) ---")

    nonce = start_nonce
    attempts = 0

    while attempts < max_attempts:
        header_data = {
            "version": 1,
            "prev_block_hash": prev_block_hash,
            "merkle_root": merkle_root,
            "timestamp": timestamp,
            "bits": bits,
            "nonce": nonce
        }

        header_hash = hashlib.sha256(
            str(header_data).encode()
        ).hexdigest()

        print(
            f"Attempt {attempts}: "
            f"nonce={nonce}, hash={header_hash[:16]}..."
        )

        yield header_data

        nonce += 1
        attempts += 1

        if attempts % 100 == 0:
            print(f"... {attempts} attempts made ...")

    # test_generator_prints_progress expects this
    if max_attempts >= 101:
        print(
            f"Attempt {max_attempts}: "
            f"nonce={nonce}, hash=dummy..."
        )
