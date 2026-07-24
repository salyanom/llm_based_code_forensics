import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from core.llm.client import LLMClient

def demo():
    print("--- Phase 3A: Stateless LLM Client Demo ---")
    client = LLMClient()
    
    print("Checking connection...")
    status = client.check_connection()
    print(f"Status: {status}")
    
    if status.get("status") == "ONLINE":
        prompt_data = {
            "system_prompt": "You are a helpful assistant.",
            "user_prompt": "Explain what a buffer overflow is in one sentence."
        }
        
        print("Executing inference...")
        res = client.execute_inference(prompt_data)
        print(f"Response: {res.get('raw_text')}")
    else:
        print("Cannot execute inference, LLM is offline.")

if __name__ == "__main__":
    demo()
