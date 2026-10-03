import argparse
from util import extract_public_key, verify_artifact_signature
from merkle_proof import DefaultHasher, verify_consistency, verify_inclusion, compute_leaf_hash
import requests
import base64
import os
import json

REKOR_URL = "https://rekor.sigstore.dev/api/v1"

def validate_log_index(log_index):
    if not isinstance(log_index, int) or log_index < 0:
        raise ValueError("log_index must be a positive number")

def get_log_entry(log_index, debug=False):
    validate_log_index(log_index)
    response = requests.get(
        f"{REKOR_URL}/log/entries",
        params={"logIndex": log_index},
        timeout=10,
    )
    response.raise_for_status()
    uuid, entry = next(iter(response.json().items()))
    return entry

def get_verification_proof(log_index, debug=False):
    # verify that log index value is sane
    validate_log_index(log_index)

    entry = get_log_entry(log_index, debug)
    proof = entry["verification"]["inclusionProof"]

    result = {
        "leaf_hash": compute_leaf_hash(entry["body"]),
        "index": proof["logIndex"],
        "tree_size": proof["treeSize"],
        "hashes": proof["hashes"],
        "root_hash": proof["rootHash"],
    }
    return result

def inclusion(log_index, artifact_filepath, debug=False):
    # extract_public_key(certificate)
    # verify_artifact_signature(signature, public_key, artifact_filepath)
    # get_verification_proof(log_index)
    # verify_inclusion(DefaultHasher, index, tree_size, leaf_hash, hashes, root_hash)
    
    # verify that log index and artifact filepath values are sane
    validate_log_index(log_index)
    if not artifact_filepath or not os.path.isfile(artifact_filepath):
        raise ValueError(f"artifact file not found: {artifact_filepath}")

    # get the entry and decode its body
    entry = get_log_entry(log_index, debug)
    body = json.loads(base64.b64decode(entry["body"]))

    signature = base64.b64decode(body["spec"]["signature"]["content"])
    certificate = base64.b64decode(body["spec"]["signature"]["publicKey"]["content"])

    # verify the signature with the key from the certificate
    public_key = extract_public_key(certificate)
    verify_artifact_signature(signature, public_key, artifact_filepath)

    # verify the entry is included in the Merkle tree
    proof = get_verification_proof(log_index, debug)
    verify_inclusion(
        DefaultHasher,
        proof["index"],
        proof["tree_size"],
        proof["leaf_hash"],
        proof["hashes"],
        proof["root_hash"],
    )
    print("Offline verification successful")

def get_latest_checkpoint(debug=False):
    # Fetch the latest checkpoint from rekor
    response = requests.get(f"{REKOR_URL}/log", timeout=10)
    response.raise_for_status()
    checkpoint = response.json()

    if debug:
        # if debug is enabled, store it in checkpoint.json
        with open("checkpoint.json", "w") as f:
            json.dump(checkpoint, f, indent=4)

    return checkpoint

def consistency(prev_checkpoint, debug=False):
    # verify that prev checkpoint is not empty
    if not prev_checkpoint:
        raise ValueError("previous checkpoint is empty")
    for key in ("treeID", "treeSize", "rootHash"):
        if not prev_checkpoint.get(key):
            raise ValueError(f"previous checkpoint missing {key}")

    # get_latest_checkpoint()
    latest = get_latest_checkpoint(debug)

    if str(prev_checkpoint["treeID"]) != str(latest["treeID"]):
        raise ValueError("the checkpoints come form different trees")
    if prev_checkpoint["treeSize"] > latest["treeSize"]:
        raise ValueError("previous tree size is larger than the current one")
    if prev_checkpoint["treeSize"] == latest["treeSize"]:
        raise ValueError("previous checkpoint is the same as the latest one")

    # ask Rekor for the consistency proof between the two sizes
    response = requests.get(
        f"{REKOR_URL}/log/proof",
        params={
            "firstSize": prev_checkpoint["treeSize"],
            "lastSize": latest["treeSize"],
            "treeID": latest["treeID"],
        },
        timeout=10,
    )
    response.raise_for_status()
    proof = response.json()
    verify_consistency(
        DefaultHasher,
        prev_checkpoint["treeSize"],
        latest["treeSize"],
        proof["hashes"],
        prev_checkpoint["rootHash"],
        latest["rootHash"],
    )
    print("Consistency verification successful")

def main():
    debug = False
    parser = argparse.ArgumentParser(description="Rekor Verifier")
    parser.add_argument('-d', '--debug', help='Debug mode',
                        required=False, action='store_true') # Default false
    parser.add_argument('-c', '--checkpoint', help='Obtain latest checkpoint\
                        from Rekor Server public instance',
                        required=False, action='store_true')
    parser.add_argument('--inclusion', help='Verify inclusion of an\
                        entry in the Rekor Transparency Log using log index\
                        and artifact filename.\
                        Usage: --inclusion 126574567',
                        required=False, type=int)
    parser.add_argument('--artifact', help='Artifact filepath for verifying\
                        signature',
                        required=False)
    parser.add_argument('--consistency', help='Verify consistency of a given\
                        checkpoint with the latest checkpoint.',
                        action='store_true')
    parser.add_argument('--tree-id', help='Tree ID for consistency proof',
                        required=False)
    parser.add_argument('--tree-size', help='Tree size for consistency proof',
                        required=False, type=int)
    parser.add_argument('--root-hash', help='Root hash for consistency proof',
                        required=False)
    args = parser.parse_args()
    if args.debug:
        debug = True
        print("enabled debug mode")
    if args.checkpoint:
        # get and print latest checkpoint from server
        # if debug is enabled, store it in a file checkpoint.json
        checkpoint = get_latest_checkpoint(debug)
        print(json.dumps(checkpoint, indent=4))
    if args.inclusion:
        inclusion(args.inclusion, args.artifact, debug)
    if args.consistency:
        if not args.tree_id:
            print("please specify tree id for prev checkpoint")
            return
        if not args.tree_size:
            print("please specify tree size for prev checkpoint")
            return
        if not args.root_hash:
            print("please specify root hash for prev checkpoint")
            return

        prev_checkpoint = {}
        prev_checkpoint["treeID"] = args.tree_id
        prev_checkpoint["treeSize"] = args.tree_size
        prev_checkpoint["rootHash"] = args.root_hash

        consistency(prev_checkpoint, debug)

if __name__ == "__main__":
    main()
