import os
import requests

DATASET_URL = "https://raw.githubusercontent.com/shreyas-sriram/Phishing-URL-Detection/master/phishing.csv"
SAVE_PATH = os.path.join(os.path.dirname(__file__), "phishing_dataset.csv")

def download_dataset():
    print(f"Attempting to download dataset from {DATASET_URL}...")
    try:
        response = requests.get(DATASET_URL, timeout=15)
        response.raise_for_status()
        
        with open(SAVE_PATH, "wb") as f:
            f.write(response.content)
            
        print(f"Successfully saved dataset to {SAVE_PATH}")
    except Exception as e:
        print(f"\n[!] Error downloading dataset: {e}")
        print("[i] If you are in a restricted environment, please manually download the CSV from the URL above.")
        print("[i] Alternatively, you can use the 'sample_dataset.csv' already in this folder for testing.")

if __name__ == "__main__":
    # Ensure directory exists
    os.makedirs(os.path.dirname(SAVE_PATH), exist_ok=True)
    download_dataset()
