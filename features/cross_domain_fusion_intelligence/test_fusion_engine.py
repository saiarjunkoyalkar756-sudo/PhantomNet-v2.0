import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

from features.cross_domain_fusion_intelligence.fusion_engine import FusionEngine

def run_fusion_engine_test():
    """
    Tests the FusionEngine's basic functionality.
    """
    print("--- Running Test Scenario: Cross-Domain Fusion Intelligence ---")
    
    fusion_engine = FusionEngine()
    
    user_id = "employee_x"
    
    # 1. Ingest data from different domains
    fusion_engine.ingest_psychological_data(user_id, {"stress_level": 0.9})
    fusion_engine.ingest_economic_data(user_id, {"unusual_transactions": 6})
    fusion_engine.ingest_linguistic_data(user_id, {"recent_communication_style": "urgent and demanding"})
    
    # 2. Make a prediction based on the fused data
    prediction = fusion_engine.predict_human_driven_attack(user_id)
    
    print(f"\n--- Prediction Result ---")
    print(prediction)
    
    # 3. Test a low-risk scenario
    user_id_2 = "employee_y"
    fusion_engine.ingest_psychological_data(user_id_2, {"stress_level": 0.3})
    fusion_engine.ingest_economic_data(user_id_2, {"unusual_transactions": 1})
    fusion_engine.ingest_linguistic_data(user_id_2, {"recent_communication_style": "calm and formal"})
    
    prediction_2 = fusion_engine.predict_human_driven_attack(user_id_2)
    
    print(f"\n--- Prediction Result for Low-Risk User ---")
    print(prediction_2)

if __name__ == "__main__":
    run_fusion_engine_test()
