import requests
import time
import hashlib
import base64
from ecdsa import VerifyingKey, SECP256k1
from ecdsa.util import sigdecode_der

# Blockchain Explorer API Endpoint (Modify for your blockchain network)
API_URL = "https://blockchain.info/block-height/{}?format=json"

SCRIPT_NAME = "SABIDZPRO"  # Your script's name

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

# Function to fetch transactions from a specific block
def fetch_transactions_from_block(block_height):
    max_retries = 3
    retry_delay = 5

    for attempt in range(max_retries):
        try:
            response = requests.get(
                API_URL.format(block_height),
                timeout=30,
                headers={'User-Agent': f'{SCRIPT_NAME}/1.0'}
            )
            if response.status_code == 429:  # Rate limit
                wait_time = int(response.headers.get('Retry-After', retry_delay))
                print(f"[{SCRIPT_NAME}] Rate limited. Waiting {wait_time} seconds...")
                time.sleep(wait_time)
                continue
            response.raise_for_status()
            block_data = response.json()
            return block_data['blocks'][0]['tx']
        except requests.exceptions.RequestException as e:
            print(f"[{SCRIPT_NAME}] Network error: {e}")
            if attempt < max_retries - 1:
                time.sleep(retry_delay)
            else:
                return []
        except (KeyError, ValueError) as e:
            print(f"[{SCRIPT_NAME}] Data parsing error: {e}")
            return []

# Function to validate a digital signature (using ecdsa)
def validate_signature(transaction):
    for input_tx in transaction.get('inputs', []):
        scriptSig = input_tx.get('script', None)
        if scriptSig:
            try:
                # Check if scriptSig is hexadecimal
                if all(c in '0123456789abcdefABCDEF' for c in scriptSig):
                    signature = bytes.fromhex(scriptSig)
                else:
                    try:
                        signature = base64.b64decode(scriptSig)
                    except Exception as e:
                        print(f"[{SCRIPT_NAME}] Base64 decoding failed: {e}")
                        return False

                pub_key_hex = input_tx.get('prev_out', {}).get('addr', '')

                if pub_key_hex:
                    vk = VerifyingKey.from_string(bytes.fromhex(pub_key_hex), curve=SECP256k1)
                    if vk.verify(signature, bytes.fromhex(transaction['hash']), sigdecode=sigdecode_der):
                        return True
                    else:
                        print(f"[{SCRIPT_NAME}] Signature verification failed for tx {transaction['hash']}")
                        return False
            except Exception as e:
                print(f"[{SCRIPT_NAME}] Signature validation failed: {e}")
                return False
    return True

# Function to check for R-value reuse in transactions
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
        print(f"[{SCRIPT_NAME}] Error processing transaction {tx['hash']}: {e}. Skipping this transaction.")
        return None

def is_p2pkh_address(address):
    if not address:
        return False
    try:
        # Check if address starts with 1 or 3 (common for P2PKH addresses)
        return address.startswith('1') or address.startswith('3')
    except:
        return False

# Function to check vulnerabilities in a transaction
def check_vulnerabilities(transaction, all_transactions, user_choices):
    vulnerabilities = []
    
    if 1 in user_choices and check_double_spend(transaction, all_transactions):
        vulnerabilities.append("Double Spend Attempt detected")
    
    if 2 in user_choices and check_transaction_malleability(transaction):
        vulnerabilities.append("Transaction Malleability Risk")
    
    if 3 in user_choices and not validate_transaction_format(transaction):
        vulnerabilities.append("Invalid Transaction Format")
    
    if 4 in user_choices and check_low_confirmations(transaction):
        vulnerabilities.append("Low Confirmation Count")
    
    if 5 in user_choices and check_dust_flooding(transaction):
        vulnerabilities.append("Potential Dust Flooding")
    
    if 6 in user_choices and check_high_fee(transaction):
        vulnerabilities.append("Unusually High Fee")
    
    if 7 in user_choices and check_address_reuse(transaction):
        vulnerabilities.append("Address Reuse Detected")
    
    if 8 in user_choices and check_r_reuse_in_tx(transaction):
        vulnerabilities.append("R-value Reuse Detected")
    
    return vulnerabilities

def validate_transaction_format(transaction):
    required_fields = ['hash', 'inputs', 'out', 'ver']
    return all(field in transaction for field in required_fields)

def check_double_spend(transaction, all_transactions):
    inputs = set(inp.get('prev_out', {}).get('hash', '') for inp in transaction.get('inputs', []))
    for tx in all_transactions:
        if tx['hash'] != transaction['hash']:
            tx_inputs = set(inp.get('prev_out', {}).get('hash', '') for inp in tx.get('inputs', []))
            if inputs & tx_inputs:
                return True
    return False

def check_transaction_malleability(transaction):
    return any(
        not input_tx.get('sequence', 0xFFFFFFFF) == 0xFFFFFFFF
        for input_tx in transaction.get('inputs', [])
    )

def check_low_confirmations(transaction):
    return transaction.get('confirmations', 0) < 6

def check_dust_flooding(transaction):
    dust_threshold = 546  # Satoshis
    dust_outputs = sum(1 for out in transaction.get('out', [])
                      if out.get('value', 0) < dust_threshold)
    return dust_outputs > 3

def check_high_fee(transaction):
    total_in = sum(inp.get('prev_out', {}).get('value', 0) 
                  for inp in transaction.get('inputs', []))
    total_out = sum(out.get('value', 0) 
                   for out in transaction.get('out', []))
    fee = total_in - total_out
    return fee > total_in * 0.1  # Fee > 10% of input value

def check_address_reuse(transaction):
    addresses = set()
    for inp in transaction.get('inputs', []):
        addr = inp.get('prev_out', {}).get('addr')
        if addr in addresses:
            return True
        addresses.add(addr)
    return False

def display_and_save_transaction(transaction_id, vulnerabilities):
    output = (
        f"[{SCRIPT_NAME}] Transaction ID: {transaction_id}\n"
        f"[{SCRIPT_NAME}] Vulnerabilities: {', '.join(vulnerabilities)}\n"
        + "-" * 50
    )
    print(output)
    with open("vulnerable_transactions.txt", "a") as file:
        file.write(output + "\n")

def get_user_choices():
    while True:
        try:
            print("Select the vulnerabilities to scan for (enter numbers separated by commas):")
            print("1. Double Spend Attack")
            print("2. Transaction Malleability")
            print("3. Invalid Transaction Format")
            print("4. Low Confirmations")
            print("5. Dust Flooding")
            print("6. Unusually High Fee")
            print("7. Address Reuse")
            print("8. R-value Reuse")
            
            choices = input("Your choices: ").strip().split(',')
            selected = set(int(choice) for choice in choices if choice.strip())
            if not all(1 <= choice <= 8 for choice in selected):
                raise ValueError("Invalid choices. Please enter numbers between 1 and 8.")
            return selected
        except ValueError as e:
            print(f"Error: {e}")

# Main script
if __name__ == "__main__":
    show_disclaimer()  # Display the disclaimer first
    print(f"Starting script... ({SCRIPT_NAME}) Press Ctrl+C to exit.")
    
    try:
        user_choices = get_user_choices()
        while True:
            try:
                block_height = int(input("Enter the block height to start scanning from: "))
                if block_height < 0:
                    raise ValueError("Block height must be positive")
                break
            except ValueError as e:
                print(f"Invalid input: {e}")
        
        all_transactions = []  # Store all transactions for double spend check
        while True:
            transactions = fetch_transactions_from_block(block_height)
            print(f"[{SCRIPT_NAME}] Fetched {len(transactions)} transactions from block {block_height}.")
            all_transactions.extend(transactions)

            found_vulnerabilities = False
            for tx in transactions:
                vulnerabilities = check_vulnerabilities(tx, all_transactions, user_choices)
                if vulnerabilities:
                    display_and_save_transaction(tx['hash'], vulnerabilities)
                    found_vulnerabilities = True
            
            if not found_vulnerabilities:
                block_height += 1  # Move to the next block if no vulnerabilities found
                print(f"[{SCRIPT_NAME}] No vulnerabilities found. Moving to block {block_height}.")
            time.sleep(10)  # Fetch new block every 10 seconds
    except KeyboardInterrupt:
        print(f"\n[{SCRIPT_NAME}] Exiting script. Goodbye!")
