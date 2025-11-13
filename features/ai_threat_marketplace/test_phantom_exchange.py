import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

from features.ai_threat_marketplace.phantom_exchange import PhantomExchange

def run_exchange_test():
    """
    Tests the PhantomExchange's core functionality.
    """
    print("--- Running Test Scenario: AI Threat Marketplace (PhantomExchange) ---")
    
    exchange = PhantomExchange()
    
    # 1. Register a new developer
    developer_id = "dev_jane_doe"
    exchange.register_developer(developer_id)
    
    # 2. Submit a new threat detection module
    module_name = "exploit_detector_v1"
    # In a real scenario, this would be actual code.
    module_code = "def detect_exploit(data): return 'exploit' in data"
    exchange.submit_module(developer_id, module_name, module_code)
    
    # 3. Validate the submitted module
    module_id = f"{developer_id}_{module_name}"
    exchange.validate_module(module_id)
    
    # 4. Check the developer's reputation and validated modules
    print(f"\n--- Final State ---")
    print(f"Developer Info: {exchange.developers[developer_id]}")
    print(f"Validated Modules: {exchange.validated_modules}")

if __name__ == "__main__":
    run_exchange_test()
