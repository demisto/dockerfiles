import os
import sys
import json
import jwt
import datetime
from typing import Any, Dict
from llama_cpp import Llama, ChatCompletionRequestSystemMessage, ChatCompletionRequestUserMessage


EXPECTED_KEY_ENV_VAR_NAME = "LLM_SERVICE_API_SECRET"
EXPECTED_API_KEY = os.environ.get(EXPECTED_KEY_ENV_VAR_NAME, "1")

JWT_ALGORITHM = "HS256"

if not EXPECTED_API_KEY:
    print(f"Configuration Error: The required environment variable '{EXPECTED_KEY_ENV_VAR_NAME}' is not set.",
          file=sys.stderr)
    sys.exit(1)

MODEL_PATH = os.environ.get("MODEL_PATH", "Meta-Llama-3.1-8B-Instruct-Q4_K_M.gguf")
N_GPU_LAYERS = int(os.environ.get("N_GPU_LAYERS", 0))


def initialize_llm() -> Llama:
    """Initializes and returns the Llama model instance."""

    if not MODEL_PATH or not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(f"Model not found at expected path: {MODEL_PATH}")

    try:
        llm_instance = Llama(
            model_path=MODEL_PATH,
            n_gpu_layers=N_GPU_LAYERS,
            n_ctx=4096,
            verbose=False
        )
        return llm_instance
    except Exception as e:
        raise RuntimeError(f"Failed to initialize LLM: {e}")



def create_auth_token(user_id: str = "llm-client") -> str:
    """
    Generates a new signed JWT containing authentication information.
    This function should be called by the client/wrapper that needs to access the API.

    :param user_id: Identifier for the client/user.
    :return: The encoded JWT string.
    """
    try:
        payload = {
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24),
            'iat': datetime.datetime.utcnow(),
            'sub': user_id
        }

        return jwt.encode(
            payload,
            EXPECTED_API_KEY,
            algorithm=JWT_ALGORITHM
        )
    except Exception as e:
        print(f"Error creating JWT: {e}", file=sys.stderr)
        raise


def decode_auth_token(auth_token: str) -> Dict[str, Any]:
    """
    Decodes and verifies the JWT. Raises exceptions on failure.

    :param auth_token: The JWT string from the client.
    :return: The decoded payload dictionary.
    :raises: jwt.InvalidTokenError on any validation failure (e.g., expiry, invalid signature).
    """
    try:
        payload = jwt.decode(
            auth_token,
            EXPECTED_API_KEY,
            algorithms=[JWT_ALGORITHM]
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise jwt.InvalidTokenError("Token has expired.")
    except jwt.InvalidAlgorithmError:
        raise jwt.InvalidTokenError("Invalid signing algorithm.")
    except jwt.InvalidSignatureError:
        raise jwt.InvalidTokenError("Token signature verification failed.")
    except jwt.PyJWTError as e:
        raise jwt.InvalidTokenError(f"JWT decoding failed: {e}")



def call_llm_api(prompt: str, auth_token: str) -> Dict[str, Any]:
    """
    Authenticates by verifying the JWT and calls the Llama model.

    :param prompt: The user's input content.
    :param auth_token: The JWT string for authentication.
    :return: The parsed JSON result from the LLM.
    :raises: PermissionError if authentication fails, or RuntimeError on LLM failure.
    """
    try:
        payload = decode_auth_token(auth_token)
        print(f"Authentication Successful. Token subject: {payload.get('sub')}")

    except jwt.InvalidTokenError as e:
        raise PermissionError(f"Authentication Failed: Invalid JWT - {e}")

    try:
        llm = initialize_llm()
    except Exception as e:
        raise RuntimeError(f"Service Error: Cannot load the LLM model. Details: {e}")

    system_prompt = """You are an expert technical analyst and helpful assistant. 
        Your task is to analyze the user's query, which often contains technical terms, code snippets, or data comparisons. 
        Your response must be **direct, concise, and professional**. 
        **OUTPUT INSTRUCTIONS:** You must respond ONLY with a single JSON object that follows this schema. Do not include any introductory or concluding text. 
        ```json { "Result": string, "Verdict":string, "Evidence": [list of relevant evidence to support the verdict]}
        """

    messages = [
        ChatCompletionRequestSystemMessage(content=system_prompt, role="system"),
        ChatCompletionRequestUserMessage(content=prompt, role="user")
    ]

    try:
        response = llm.create_chat_completion(
            messages=messages,
            max_tokens=4096,
            repeat_penalty=1.1,
            top_p=0.9,
            top_k=40,
            temperature=0.03
        )

        response_text = response['choices'][0]['message']['content'].strip()

        try:
            return json.loads(response_text)
        except json.JSONDecodeError:
            if response_text.startswith("```json"):
                cleaned_text = response_text.replace("```json", "", 1).strip()
                if cleaned_text.endswith("```"):
                    cleaned_text = cleaned_text[:-3].strip()

                try:
                    return json.loads(cleaned_text)
                except json.JSONDecodeError as inner_e:
                    print(f"Warning: Failed to parse JSON even after cleaning. Details: {inner_e}", file=sys.stderr)

            print(f"Warning: LLM did not return valid JSON. Raw response: {response_text}", file=sys.stderr)
            return {"Error": "LLM response was not valid JSON", "RawResponse": response_text}

    except Exception as e:
        raise RuntimeError(f"An error occurred during LLM generation: {e}")



def call_llm(prompt: str, auth_token: str) -> Dict[str, Any]:
    try:
        return call_llm_api(prompt, auth_token)
    except PermissionError as e:
        return {"Error": str(e), "Code": 401}
    except RuntimeError as e:
        return {"Error": str(e), "Code": 500}
    except Exception as e:
        return {"Error": f"An unexpected error occurred: {e}", "Code": 500}
