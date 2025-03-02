import requests
import time
import hashlib
import base64
from ecdsa import VerifyingKey, SECP256k1
from ecdsa.util import sigdecode_der

# Blockchain Explorer API Endpoint (Modify for your blockchain network)
API_URL = "https://blockchain.info/unconfirmed-transactions?format=json"

SCRIPT_NAME = "CRYPTOGRAPHYTUBE"  # Your script's name

# Display Disclaimer
def show_disclaimer():
    disclaimer = f"""
    ****************************************************************************************
    *                                                                                      *
    *   DISCLAIMER: This script is developed by {SCRIPT_NAME} for educational purposes     *
    *   only. Unauthorized use of this script for malicious activities or misuse of the    *
    *   information generated is strictly prohibited.                                      *
    *                                                                                      *
    *   By using this script, you agree that {SCRIPT_NAME} is not responsible for any      *
    *   misuse, damages, or illegal activities resulting from its use.                     *
    *                                                                                      *
    ****************************************************************************************
    """
    print(disclaimer)
    input("Press Enter to proceed...")  # Wait for the user to acknowledge

# Function to fetch unconfirmed transactions
def fetch_unconfirmed_transactions():
    try:
        response = requests.get(API_URL)
        if response.status_code == 200:
            transactions = response.json()
            return transactions['txs']
        else:
            print(f"[{SCRIPT_NAME}] Error: Unable to fetch transactions, Status Code: {response.status_code}")
            return []
    except Exception as e:
        print(f"[{SCRIPT_NAME}] Exception: {e}")
        return []

# Function to validate a digital signature (using ecdsa)
def validate_signature(transaction):
    for input_tx in transaction.get('inputs', []):
        scriptSig = input_tx.get('script', None)  # Example: Signature in the scriptSig field
        if scriptSig:
            try:
                # Check if scriptSig is hexadecimal
                if all(c in '0123456789abcdefABCDEF' for c in scriptSig):  # Check if valid hex
                    signature = bytes.fromhex(scriptSig)
                else:
                    # Try Base64 decoding if not hexadecimal
                    try:
                        signature = base64.b64decode(scriptSig)
                    except Exception as e:
                        print(f"[{SCRIPT_NAME}] Base64 decoding failed: {e}")
                        return False

                pub_key_hex = input_tx.get('prev_out', {}).get('addr', '')  # Placeholder public key

                # Public key verification
                if pub_key_hex:
                    vk = VerifyingKey.from_string(bytes.fromhex(pub_key_hex), curve=SECP256k1)

                    # Verify the signature with the transaction hash
                    if vk.verify(signature, bytes.fromhex(transaction['hash']), sigdecode=sigdecode_der):
                        return True
                    else:
                        print(f"[{SCRIPT_NAME}] Signature verification failed for tx {transaction['hash']}")
                        return False
            except Exception as e:
                print(f"[{SCRIPT_NAME}] Signature validation failed: {e}")
                return False
    return True  # Assume valid if no signature provided (can adjust as needed)

# Function to select vulnerabilities to check
def select_vulnerabilities():
    print("Select vulnerabilities to check (comma-separated numbers):")
    print("1. Double Spend Attack")
    print("2. Transaction Malleability")
    print("3. Invalid Transaction Format")
    print("4. Low Confirmations")
    print("5. Dust Flooding")
    print("6. Unusually High Fee")
    print("7. Address Reuse")
    print("8. ASM Hex Reuse")
    print("9. Reused R-Value or Script Duplicates")
    selected = input("Enter your choices: ")
    return set(map(int, selected.split(',')))

# Function to check for reused R values or script duplicates in a transaction
def check_r_reuse_in_tx(tx):
    inputs = [inp['script'] for inp in tx.get('inputs', []) if 'script' in inp]
    outputs = [out['script'] for out in tx.get('out', []) if 'script' in out]
    all_scripts = inputs + outputs
    
    try:
        r_values = [script[10:74] for script in all_scripts if len(script) > 74]
        
        duplicates = {}
        for idx, r in enumerate(r_values):
            if r in duplicates:
                duplicates[r].append(idx)
            else:
                duplicates[r] = [idx]
        
        reused_r = {r: idx_list for r, idx_list in duplicates.items() if len(idx_list) > 1}
        return reused_r
    except Exception as e:
        print(f"Error processing transaction {tx['hash']}: {e}. Skipping this transaction.")
        return None

# Function to check vulnerabilities in a transaction
def check_vulnerabilities(transaction, all_transactions, selected_vulnerabilities):
    vulnerabilities = set()

    # 1. Double Spend Attack
    if 1 in selected_vulnerabilities:
        for input_tx in transaction.get('inputs', []):
            prev_out = input_tx.get('prev_out', {})
            if 'hash' in prev_out:  # Check if 'hash' exists in prev_out
                input_tx_hash = prev_out['hash']
                for existing_tx in all_transactions:
                    if existing_tx['hash'] == input_tx_hash:
                        vulnerabilities.add("Double Spend Attack (Same Input Detected in Another Transaction)")

    # 2. Transaction Malleability
    if 2 in selected_vulnerabilities:
        if not validate_signature(transaction):
            vulnerabilities.add("Transaction Malleability (Signature Manipulation Detected)")

    # 3. Invalid Transaction Format
    if 3 in selected_vulnerabilities:
        if 'inputs' not in transaction or 'out' not in transaction:
            vulnerabilities.add("Invalid Transaction Format (Missing Inputs or Outputs)")

    # 4. Low Confirmations
    if 4 in selected_vulnerabilities:
        if transaction.get('confirmations', 0) < 1:
            vulnerabilities.add("Low Confirmations (High-Risk Transaction)")

    # 5. Dust Flooding
    if 5 in selected_vulnerabilities:
        total_input_value = sum([input_tx['prev_out']['value'] for input_tx in transaction.get('inputs', []) if 'prev_out' in input_tx])
        total_output_value = sum([output['value'] for output in transaction.get('out', [])])
        if total_input_value < 1000 and total_output_value < 1000:
            vulnerabilities.add("Dust Flooding (Small Inputs and Outputs)")

    # 6. Unusually High Fee
    if 6 in selected_vulnerabilities:
        if transaction.get('fee', 0) > 100000:  # Fee threshold (adjust as needed)
            vulnerabilities.add("Unusually High Transaction Fee")

    # 7. Address Reuse
    if 7 in selected_vulnerabilities:
        seen_addresses = set()
        for input_tx in transaction.get('inputs', []):
            address = input_tx.get('prev_out', {}).get('addr', None)
            if address and address in seen_addresses:
                vulnerabilities.add(f"Address Reuse (Address {address} Reused)")
            seen_addresses.add(address)

    # 8. ASM Hex Reuse
    if 8 in selected_vulnerabilities:
        asm_hex = transaction.get('asm', None)
        if asm_hex:
            for existing_tx in all_transactions:
                if existing_tx.get('asm') == asm_hex:
                    vulnerabilities.add("ASM Hex Reuse (Same ASM Hex Detected in Another Transaction)")

    # 9. Reused R-Value or Script Duplicates
    if 9 in selected_vulnerabilities:
        reused_r = check_r_reuse_in_tx(transaction)
        if reused_r:
            vulnerabilities.add("Reused R-Value or Script Duplicates Detected")

    return list(vulnerabilities)

# Function to display and save vulnerable transactions
def display_and_save_transaction(transaction_id, vulnerabilities):
    output = (
        f"[{SCRIPT_NAME}] Transaction ID: {transaction_id}\n"
        f"[{SCRIPT_NAME}] Vulnerabilities: {', '.join(vulnerabilities)}\n"
        + "-" * 50
    )
    print(output)
    with open("vulnerable_transactions.txt", "r+") as file:
        existing_content = file.read()
        if transaction_id not in existing_content:
            file.write(output + "\n")

# Function to select a block to scan
def select_block():
    block = input("Enter the block hash or block height to scan: ")
    return block

# Function to fetch transactions from a specific block
def fetch_transactions_from_block(block):
    try:
        response = requests.get(f"https://blockchain.info/rawblock/{block}")
        if response.status_code == 200:
            transactions = response.json()
            return transactions['tx']
        else:
            print(f"[{SCRIPT_NAME}] Error: Unable to fetch transactions for block {block}, Status Code: {response.status_code}")
            return []
    except Exception as e:
        print(f"[{SCRIPT_NAME}] Exception: {e}")
        return []

# Main script
if __name__ == "__main__":
    show_disclaimer()  # Display the disclaimer first
    block = select_block()  # Select block to scan
    selected_vulnerabilities = select_vulnerabilities()  # Select vulnerabilities to check
    print(f"Starting script... ({SCRIPT_NAME}) Press Ctrl+C to exit.")
    try:
        all_transactions = []  # Store all transactions for double spend check
        scanned_transactions = set()  # Track scanned transactions
        while True:
            transactions = fetch_transactions_from_block(block)
            print(f"[{SCRIPT_NAME}] Fetched {len(transactions)} transactions from block {block}.")
            all_transactions.extend(transactions)

            found_vulnerabilities = False
            for tx in transactions:
                if tx['hash'] not in scanned_transactions:
                    vulnerabilities = check_vulnerabilities(tx, all_transactions, selected_vulnerabilities)
                    if vulnerabilities:
                        display_and_save_transaction(tx['hash'], vulnerabilities)
                        found_vulnerabilities = True
                    scanned_transactions.add(tx['hash'])

            block = str(int(block) + 1)  # Automatically increment block number
            time.sleep(10)  # Fetch new transactions every 10 seconds
    except KeyboardInterrupt:
        print(f"\n[{SCRIPT_NAME}] Exiting script. Goodbye!")