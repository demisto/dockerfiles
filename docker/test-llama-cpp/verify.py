import os
import sys
import requests
from llama_cpp import Llama

MODEL_PATH = os.environ.get("LLAMA_MODEL_PATH")
if not MODEL_PATH:
    print("Error: LLAMA_MODEL_PATH environment variable not set.")
    sys.exit(1)

if not os.path.exists(MODEL_PATH):
    print(f"Error: Model file not found at {MODEL_PATH}")
    sys.exit(1)

print(f"Successfully found model file at {MODEL_PATH}")