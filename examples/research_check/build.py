"""Fixed public-data example producer; never invoked by receipt verification."""
from provenance_core import canonical_json_bytes


def produce() -> bytes:
    return canonical_json_bytes({"z": [None, True, False, 42], "a": "café\n"})


if __name__ == "__main__":
    import sys
    sys.stdout.buffer.write(produce())
