import time

class PhantomExchange:
    """
    Global platform for AI-driven threat intelligence and detection modules.
    Third-party developers earn rewards for validated contributions.
    """
    def __init__(self, phantom_chain=None):
        self.developers = {}
        self.modules = {}
        self.validated_modules = set()
        self.phantom_chain = phantom_chain
        print("Initializing PhantomExchange (AI Threat Marketplace)...")

    def register_developer(self, developer_id: str):
        """
        Registers a new developer on the platform.
        """
        if developer_id not in self.developers:
            self.developers[developer_id] = {"reputation": 100, "submissions": []}
            print(f"Developer {developer_id} registered successfully.")
            return True
        else:
            print(f"Developer {developer_id} is already registered.")
            return False

    def submit_module(self, developer_id: str, module_name: str, module_code: str):
        """
        Allows a registered developer to submit a new threat detection module.
        """
        if developer_id not in self.developers:
            print("Developer not registered. Please register first.")
            return False
        
        module_id = f"{developer_id}_{module_name}"
        self.modules[module_id] = {
            "code": module_code,
            "developer": developer_id,
            "validated": False
        }
        self.developers[developer_id]["submissions"].append(module_id)
        print(f"Module {module_id} submitted successfully.")
        return True

    def validate_module(self, module_id: str):
        """
        Simulates the validation of a submitted module and records it on the PhantomChain.
        """
        if module_id not in self.modules:
            print("Module not found.")
            return False
            
        print(f"Validating module {module_id}...")
        time.sleep(1) # Simulate validation time
        
        if self.modules[module_id]["code"]:
            self.modules[module_id]["validated"] = True
            self.validated_modules.add(module_id)
            developer_id = self.modules[module_id]["developer"]
            self.developers[developer_id]["reputation"] += 10
            print(f"Module {module_id} validated successfully.")

            # Add the validation event to the PhantomChain
            if self.phantom_chain:
                transaction_data = {
                    "type": "module_validation",
                    "module_id": module_id,
                    "developer": developer_id,
                    "status": "validated",
                    "reputation_reward": 10
                }
                self.phantom_chain.add_block(transaction_data)
            return True
        else:
            print(f"Module {module_id} validation failed.")
            return False
