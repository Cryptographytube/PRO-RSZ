import concurrent.futures  # Fix the import
import requests
import time
import hashlib
import base64
import psutil  # Add psutil for CPU monitoring
from ecdsa import VerifyingKey, SECP256k1
from ecdsa.util import sigdecode_der
from multiprocessing import Pool, cpu_count
from functools import lru_cache
from requests.adapters import HTTPAdapter
import urllib3
from urllib3.util.retry import Retry
import warnings
from datetime import datetime
from colorama import init, Fore, Style

# Suppress InsecureRequestWarning
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

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

# Replace the old retry import with direct urllib3 usage
def create_session():
    """Create a session with proper retry handling and SSL verification"""
    session = requests.Session()
    retry_strategy = Retry(
        total=5,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
    )
    adapter = HTTPAdapter(
        max_retries=retry_strategy,
        pool_connections=10,
        pool_maxsize=10
    )
    session.mount('https://', adapter)
    session.mount('http://', adapter)
    session.verify = False  # Disable SSL verification if needed
    return session

# Function to fetch transactions from a specific block
def fetch_transactions_from_block(block_height, session=None):
    """Fetch transactions with improved error handling"""
    if session is None:
        session = create_session()
    
    try:
        response = session.get(
            API_URL.format(block_height),
            timeout=30,
            headers={
                'User-Agent': f'{SCRIPT_NAME}/1.0',
                'Accept': 'application/json'
            }
        )
        
        if response.status_code == 429:  # Rate limit
            retry_after = int(response.headers.get('Retry-After', 30))
            print(f"[{SCRIPT_NAME}] Rate limited. Waiting {retry_after} seconds...")
            time.sleep(retry_after)
            return fetch_transactions_from_block(block_height, session)
            
        response.raise_for_status()
        block_data = response.json()
        return block_data.get('blocks', [{}])[0].get('tx', [])
        
    except requests.exceptions.Timeout:
        print(f"[{SCRIPT_NAME}] Timeout fetching block {block_height}. Retrying...")
        time.sleep(5)
        return fetch_transactions_from_block(block_height, session)
        
    except requests.exceptions.RequestException as e:
        print(f"[{SCRIPT_NAME}] Error fetching block {block_height}: {str(e)}")
        return []

# Cache validation results
@lru_cache(maxsize=1000)
def validate_signature_cached(tx_hash, script_sig, pub_key_hex):
    try:
        signature = bytes.fromhex(script_sig) if all(c in '0123456789abcdefABCDEF' for c in script_sig) \
            else base64.b64decode(script_sig)
        
        if pub_key_hex:
            vk = VerifyingKey.from_string(bytes.fromhex(pub_key_hex), curve=SECP256k1)
            return vk.verify(signature, bytes.fromhex(tx_hash), sigdecode=sigdecode_der)
    except Exception:
        return False
    return False

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

# Add timestamp function
def get_timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# Initialize colorama for cross-platform colored output
init()

def display_and_save_transaction(transaction_id, vulnerabilities):
    timestamp = get_timestamp()
    
    # Terminal output with colors
    print(f"\n{Fore.RED}[!] Vulnerable Transaction Detected{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[{timestamp}] [{SCRIPT_NAME}]{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Transaction ID:{Style.RESET_ALL} {transaction_id}")
    print(f"{Fore.CYAN}Vulnerabilities:{Style.RESET_ALL}")
    for vuln in vulnerabilities:
        print(f"  {Fore.RED}• {vuln}{Style.RESET_ALL}")
    print(f"{Fore.WHITE}{'-' * 50}{Style.RESET_ALL}")

    # File output
    output = (
        f"[{SCRIPT_NAME}] Transaction ID: {transaction_id}\n"
        f"[{SCRIPT_NAME}] Vulnerabilities: {', '.join(vulnerabilities)}\n"
        + "-" * 50
    )
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

# Process transactions in parallel
def process_transaction_batch(transactions, user_choices):
    with Pool(processes=cpu_count()) as pool:
        return pool.starmap(check_vulnerabilities, 
                          [(tx, transactions, user_choices) for tx in transactions])

# Add CPU monitoring function
def get_cpu_usage():
    cpu_percent = psutil.cpu_percent(interval=1)
    memory_percent = psutil.virtual_memory().percent
    return f"CPU: {cpu_percent}% | RAM: {memory_percent}%"

# Main script
if __name__ == "__main__":
    show_disclaimer()  # Display the disclaimer first
    print(f"Starting script... ({SCRIPT_NAME}) Press Ctrl+C to exit.")
    
    try:
        user_choices = get_user_choices()
        session = create_session()
        
        # Simplified thread count selection
        cpu_count_available = cpu_count()
        while True:
            try:
                thread_count = int(input(f"Threads (1-{cpu_count_available}): "))
                if 1 <= thread_count <= cpu_count_available:
                    break
                print(f"Enter 1-{cpu_count_available}")
            except ValueError:
                print("Invalid input")

        while True:
            try:
                block_height = int(input("Start block height: "))
                if block_height < 0:
                    raise ValueError("Must be positive")
                break
            except ValueError as e:
                print(f"Invalid input: {e}")
        
        processed_blocks = set()
        all_transactions = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=thread_count) as executor:
            while True:
                try:
                    if block_height in processed_blocks:
                        block_height += 1
                        continue
                    
                    transactions = fetch_transactions_from_block(block_height, session)
                    if transactions:
                        print(f"[{get_timestamp()}] [{SCRIPT_NAME}] Fetched {len(transactions)} transactions from block {block_height}.")
                    
                        batch_size = 100
                        for i in range(0, len(transactions), batch_size):
                            batch = transactions[i:i + batch_size]
                            futures = [executor.submit(check_vulnerabilities, tx, transactions, user_choices) 
                                     for tx in batch]
                            
                            for future in concurrent.futures.as_completed(futures):
                                try:
                                    vulnerabilities = future.result(timeout=30)
                                    if vulnerabilities:
                                        tx_hash = batch[futures.index(future)]['hash']
                                        display_and_save_transaction(tx_hash, vulnerabilities)
                                except concurrent.futures.TimeoutError:
                                    continue
                    
                    processed_blocks.add(block_height)
                    print(f"[{get_timestamp()}] [{SCRIPT_NAME}] Moving to block {block_height + 1}.")
                    block_height += 1
                    time.sleep(5)
                    
                except KeyboardInterrupt:
                    raise
                except Exception as e:
                    time.sleep(10)
                    
    except KeyboardInterrupt:
        print(f"\n[{SCRIPT_NAME}] Exiting script.")
    finally:
        if session:
            session.close()
