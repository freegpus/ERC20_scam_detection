from goplus.token import Token
from goplus.rug_pull import RugPull
import requests
import json
import sys

# Define which attributes return a 1 as safe and their risk scores
safe_attributes_scores = {
    'is_open_source': 5,
    'is_in_dex': 3,  # Part of the non-critical risks condition
    'is_true_token': 5,
    'personal_slippage_modifiable': 3  # Part of the non-critical risks condition
}

risk_scores = {
    'is_proxy': 5, 'is_mintable': 4.5, 'can_take_back_ownership': 5, 'owner_change_balance': 5,
    'hidden_owner': 5, 'is_honeypot': 5, 'transfer_pausable': 4.5, 'is_blacklisted': 4.5,
    'gas_abuse': 5, 'cannot_sell_all': 5, 'anti_whale_modifiable': 5,
    'trading_cooldown': 5, 'is_airdrop_scam': 5, 'selfdestruct': 4.5,
    'cannot_buy': 5, 'owner_percent': 5, 'creator_percent': 5, 
    'external_call': 3  # Part of the non-critical risks condition
}

def fetch_token_sec_data(address, chain_num):
    if chain_num == 2:
        chain_num = 8453

    data = Token(access_token=None).token_security(
        chain_id=str(chain_num),
        addresses=[address],
        **{"_request_timeout": 10}
    )

    token_sec_data_json = getattr(data, 'result', {})
    return token_sec_data_json.get(address.lower(), {})
    


def fetch_rug_pull_data(address, chain_num):
    rug_pull_api = RugPull()

    if chain_num == 2:
        chain_num = 8453

    data = rug_pull_api.rug_pull_security(chain_id=str(chain_num), address=address)

    # Check the type and attributes of the result
    if not hasattr(data, 'result'):
        print("No 'result' attribute found in the response.")
        return {}

    # Assuming the 'result' object has attributes matching your keys
    result = data.result  # Adjust this line based on the actual structure

    # Try accessing attributes directly if 'result' is not a dictionary
    try:
        extracted_data = {
            'privilege_withdraw': getattr(result, 'privilege_withdraw'),
            'withdraw_missing': getattr(result, 'withdraw_missing'),
            'approval_abuse': getattr(result, 'approval_abuse')
        }
    except:
        print("Rug pull data failed to fetch properly")
        return 

    return extracted_data


def analyze_token_risk(token_attributes):
    max_risk_score = 0
    failing_risks = []
    passing_risks = []
    combined_condition_count = 0
    proxy_found = False

    # Check risk-indicating attributes
    for attribute, score in risk_scores.items():
        attribute_value = getattr(token_attributes, attribute, None)
        if attribute_value == '1':  # Risk condition met
    
            if attribute == 'is_proxy':
                proxy_found = True
            #non critical risk conditions
            if attribute == 'personal_slippage_modifiable':
                combined_condition_count += 1
            if attribute == 'external_call':
                combined_condition_count += 1
            if attribute == 'is_mintable':
                print("Mintable")
            if attribute == 'is_blacklisted':
                print("Blacklistable")
            if attribute == 'transfer_pausable':
                print("Transfer can be paused")
            if attribute == 'selfdestruct':
                print("Token can be self-destructed")
            failing_risks.append(attribute)
            max_risk_score = max(max_risk_score, score)
        else:
            #special critical risk conditions
            if attribute == 'owner_percent':
                try:
                    if float(attribute_value) >= 0.15:
                        failing_risks.append(attribute)
                        max_risk_score = max(max_risk_score, score)
                        # Format the attribute value from a fraction to a percentage string
                        percentage_display = "{:.2f}%".format(float(attribute_value) * 100)
                        print(f"\nOwner owns 15 percent or more of the supply: {percentage_display} (out of 100% of total supply)")

                        continue
                except:
                    print("Issue retreiving owner percentage")
            if attribute == 'creator_percent':
                try:
                    if float(attribute_value) >= 0.15:
                        failing_risks.append(attribute)
                        # Format the attribute value from a fraction to a percentage string
                        percentage_display = "{:.2f}%".format(float(attribute_value) * 100)
                        print(f"\nCreator owns 15 percent or more of the supply: {percentage_display}  (out of 100% of total supply)")
                        continue
                except:
                    print("Issue retreiving creator percentage")
            if attribute == 'is_in_dex' and attribute_value == '0':
                combined_condition_count += 1
                continue
            passing_risks.append(attribute)


    if combined_condition_count >= 3:
        max_risk_score = 4.5
        print("Three or more non-critical risks failed.")

    # Check safe attributes
    for attribute, score in safe_attributes_scores.items():
        attribute_value = getattr(token_attributes, attribute, None)
        if attribute_value == '0':  # Safe condition not met, considered a risk
            failing_risks.append(attribute)
            max_risk_score = max(max_risk_score, score)

    return max_risk_score, failing_risks, passing_risks, proxy_found

def analyze_rug_risks(rug_data):

    # Process rug pull results and integrate them into the risk analysis
    rug_score = 1
    rug_pull_failing_risks = []
    for risk, value in rug_data.items():
        if value == '1' or value == '-1':  # Check if risk is active (assuming '1' is active)
            rug_pull_failing_risks.append(risk)
            rug_score = 5

    return rug_score, rug_pull_failing_risks

def run_combined_analysis():
    proxy_found = False
    
    address = input("Please enter the contract address for analysis: ").strip()
    chain_id = int(input("Please input the number of the chain you want to use: 1 for Ethereum Mainnet, 2 for Base mainnet: ").strip())

    if not address.startswith("0x") or len(address) != 42:
        print("The entered address does not appear to be a valid Ethereum address. Please check and try again.")
        return

    # Ensure that the chain_id input is valid and convert to integer
    try:
        if chain_id not in [1, 2]:
            print("Please select the proper chain using numbers 1 or 2 followed by the return key")
            return
    except ValueError:
        print("Invalid input for chain ID. Please enter a numeric value (1 or 2).")
        return
    
    print("\nAnalysis Results:")

    if chain_id == 2:
        creator_address = check_base_contract_creator(address)
        #add the new factory address here and create another condition once deployed
        factory_address = "0xf23d369d7471bd9f6487e198723eea023389f1d4"
        if creator_address and creator_address.lower() == factory_address.lower():
            sys.exit("This contract is an OptimismMintableERC20 deployed by the standard Base factory. There is no risk with this contract. Exiting analysis.")
        else:
            print("This contract is NOT an OptimismMintableERC20 deployed by the standard Base factory. Running additional analysis")

    token_sec_data = fetch_token_sec_data(address, chain_id)
    rug_pull_data = fetch_rug_pull_data(address, chain_id)

    token_risk_score, token_failing_risks, passing_risks_final, proxy_found = analyze_token_risk(token_sec_data)

    if proxy_found or not token_sec_data or not rug_pull_data: 
        print("Issue querying token data, running Hexagate analysis: ")
        query_hexagate(address, chain_id)
    else: 
        rug_pull_risk_score, rug_pull_failing_risks = analyze_rug_risks(rug_pull_data)

        combined_risk_score = max(token_risk_score, rug_pull_risk_score)
        combined_failing_risks = token_failing_risks + rug_pull_failing_risks
        print(f"\nOverall Risk Score: {combined_risk_score}")
        if passing_risks_final:
            print(f"\nPassing risks: {', '.join(passing_risks_final)}")
        if combined_failing_risks:
            print(f"\nFailing risks: {', '.join(combined_failing_risks)}")
        
        if combined_risk_score > 4:
            risk_category = 'HIGH risk'
        elif combined_risk_score >= 3:
            risk_category = 'MODERATE risk'
        else:
            risk_category = 'LOW risk - Passes security checks'

        print(f"This contract is considered {risk_category}.")

def query_hexagate(address, chain_num):
    HEXAGATE_API_KEY = ''  # Ensure this is correctly set
    # Validate chain_num and set URL accordingly
    if chain_num == 1:
        url = "https://api.hexagate.com/api/v1/ethereum/mainnet/address/analyze"
    elif chain_num == 2:
        url = "https://api.hexagate.com/api/v1/base/mainnet/address/analyze"
    else:
        print("Invalid chain number. Please use 1 for Ethereum Mainnet or 2 for Base mainnet.")
        return

    payload = json.dumps({"address": address})
    headers = {
        'Content-Type': 'application/json',
        'X-Hexagate-Api-Key': HEXAGATE_API_KEY
    }

    response = requests.post(url, headers=headers, data=payload)
    if response.status_code == 200:
        process_hexagate_response(response.json())
    else:
        print(f"Failed to fetch data from Hexagate. Status Code: {response.status_code}. Manual review required.")

def process_hexagate_response(response):
    # Extract primary details
    contract_name = response.get("name", "Unknown Name")
    contract_type = response.get("type", "Unknown Type")

    print(f"Contract Name: {contract_name}, Type: {contract_type}")

    if str(contract_type) == 'EOA':
        sys.exit("This is an EOA address. Please input a contract address")


    # Risk types and scores
    relevant_types_scores = {
        "DEPLOYER_RISK_ANALYSIS": 5, "ADDRESS_INTERACTED_WITH_AN_ILLICIT_ENTITY": 5, 
        "ADDRESS_REPORTED_AS_FRAUDULENT": 5, "SMARTCONTRACT_ABNORMAL_OUTFLOW_TO_INFLOW_RATIO": 4,
        "SMARTCONTRACT_ACCEPT_FUNDS_BUT_ONLY_OWNER_CAN_WITHDRAW": 5,
        "SMARTCONTRACT_HAS_SELFDESTRUCT": 5, "SMARTCONTRACT_IMPLEMENTS_ANTI_SIMULATION_TECHNIQUES": 5,
        "SMARTCONTRACT_IMPLEMENTS_PAUSABLE_FUNCTIONALITY": 5, "SMARTCONTRACT_IMPLEMENTS_MODIFIABLE_FEE_FUNCTIONALITY": 3.5,
        "ADDRESS_IS_A_NEW_ONE": 3, "SMARTCONTRACT_IMPLEMENTS_CENSORING_FUNCTIONALITY": 5, 
        "SMARTCONTRACT_IMPLEMENTS_OWNABLE_FUNCTIONALITY": 5, "FAKE_TOKEN_ADDRESS": 5, "SMARTCONTRACT_IS_UNVERIFIED": 5
    }

    # Initialize collections for issues
    security_issues = response.get("security_issues", [])
    failing_issues = []
    passing_issues = []
    max_risk_score = 1
    # Flags to check specific conditions
    all_non_critical_failed = True

    # Checking flags for specific issues
    non_critical_issues = {"SMARTCONTRACT_IMPLEMENTS_MODIFIABLE_FEE_FUNCTIONALITY", "ADDRESS_IS_A_NEW_ONE", "SMARTCONTRACT_ABNORMAL_OUTFLOW_TO_INFLOW_RATIO"}
    non_critical_statuses = {issue: False for issue in non_critical_issues}

    # Process each issue
    for issue in security_issues:
        issue_type = issue.get("type")
        if issue_type in relevant_types_scores:
            result = issue.get("result")
            risk_score = relevant_types_scores[issue_type]
            extra_details = ", ".join([f"{key}: {value}" for key, value in issue.get("extra_details", {}).items()])

            # Manage failing and passing issues
            if result:
                failing_issues.append(f"- {issue_type}: {extra_details}")
                max_risk_score = max(max_risk_score, risk_score)
                if issue_type in non_critical_statuses:
                    non_critical_statuses[issue_type] = True  # Mark this issue as failed
                if issue_type == 'SMARTCONTRACT_IMPLEMENTS_PAUSABLE_FUNCTIONALITY':
                    print("\nPausing present: please provide the following for the private key for the pausing privilege: (1)The addresses of the key(s), and whether they're cold/hot wallets & (2) an attestation/claim that key actioners are separate and vetted, privileged personnel (and whether or not they have signed NDAs), and actioning of the key(s) can only be done those privileged and vetted authorities.") 
                if issue_type == 'SMARTCONTRACT_IMPLEMENTS_OWNABLE_FUNCTIONALITY':
                    print("\nAdditional ownership detected: please provide the following for the private key for this privilege: (1) What the additional privilege is (2)The addresses of the key(s), and whether they're cold/hot wallets & (3) an attestation/claim that key actioners are separate and vetted, privileged personnel (and whether or not they have signed NDAs), and actioning of the key(s) can only be done those privileged and vetted authorities.") 
                if issue_type == 'SMARTCONTRACT_IMPLEMENTS_CENSORING_FUNCTIONALITY':
                    print("\nBlacklisting present: please provide the following for the private key for the blacklist privilege: (1)The addresses of the key(s), and whether they're cold/hot wallets & (2) an attestation/claim that key actioners are separate and vetted, privileged personnel (and whether or not they have signed NDAs), and actioning of the key(s) can only be done those privileged and vetted authorities.")
                if issue_type == 'SMARTCONTRACT_HAS_SELFDESTRUCT':
                    print("\nSelf destruct present: please provide the following for the private key for the pausing privilege: (1)The addresses of the key(s), and whether they're cold/hot wallets & (2) an attestation/claim that key actioners are separate and vetted, privileged personnel (and whether or not they have signed NDAs), and actioning of the key(s) can only be done those privileged and vetted authorities.")                
            else:
                if issue_type == 'DEPLOYER_RISK_ANALYSIS':
                    passing_issues.append(f"- {issue_type}")
                else:
                    passing_issues.append(f"- {issue_type} {extra_details}")

    # Check if all specific non-critical risks failed
    if all(non_critical_statuses.values()):
        max_risk_score = 4.5
        print("All non-critical risks failed. Adjusting score to 4.5.")

    # Output results
    print("\nPassing Security Issues:")
    if passing_issues:
        for issue in passing_issues:
            print(issue)
    else:
        print("No passing security issues according to Hexagate.")

    print("\nFailing Security Issues:")
    if failing_issues:
        for issue in failing_issues:
            print(issue)
    else:
        print("No failing security issues according to Hexagate.")

    print(f"Overall Assessment Score: {max_risk_score}")
    print(f"This contract is considered {'HIGH risk' if max_risk_score >= 4.5 else 'LOWER risk'}.")

def check_base_contract_creator(contract_address):
    API_KEY = ''
    url = f"https://api.basescan.org/api?module=account&action=txlistinternal&address={contract_address}&startblock=0&endblock=27025780&sort=asc&apikey={API_KEY}"

    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            if data["status"] == "1" and data["message"] == "OK":
                transactions = data["result"]
                if transactions:
                    creation_tx = transactions[0]  #first internal transaction is the creation
                    if creation_tx['type'] == "create":
                        creator_address = creation_tx['from']
                        print(f"Contract {contract_address} was created by {creator_address}")
                        return creator_address
                else:
                    print(f"{contract_address} Is not an OptimismMintableERC20 token")
            else:
                print("Error fetching transaction data:", data["message"])
        else:
            print("Failed to connect to Basescan API.")
    except: 
        print("Error retrieving contract creator via Basescan API")


    return None

run_combined_analysis()
