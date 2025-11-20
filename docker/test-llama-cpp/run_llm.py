import os
import sys
import json
import jwt
import datetime
from typing import Optional, Any, Dict
from llama_cpp import Llama, ChatCompletionRequestSystemMessage, ChatCompletionRequestUserMessage

MODEL_PATH = os.environ.get("MODEL_PATH", "Meta-Llama-3.1-8B-Instruct-Q4_K_M.gguf")
C_WIN = 2048

class LLMServiceError(Exception):
    """Base exception for LLM Service errors."""
    pass


class AuthenticationError(LLMServiceError):
    """Exception for JWT or general authentication failures (Code 401)."""
    pass


class InitializationError(LLMServiceError):
    """Exception for errors during LLM or model path initialization (Code 500)."""
    pass


class LLMGenerationError(LLMServiceError):
    """Exception for errors during the LLM's chat completion process (Code 500)."""
    pass

EXPECTED_API_KEY = os.environ.get("LLM_SERVICE_API_SECRET", "1")

def create_auth_token(secret_key: str, user_id: str = "llm-client", algorithm: str = "HS256") -> str:
    """
    Utility function used by the CLIENT component to generate the JWT.
    The client uses its pre-shared secret_key to sign the token.
    """
    try:
        payload = {
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24),
            'iat': datetime.datetime.utcnow(),
            'sub': user_id
        }
        return jwt.encode(payload, secret_key, algorithm=algorithm)
    except Exception as e:
        raise RuntimeError(f"Error creating JWT: {e}")


class LLMService:
    """
    Manages the LLM instance and provides a single public interface
    that accepts a pre-generated JWT for authorization.
    """
    _llm_instance: Optional[Llama] = None

    def __init__(self, expected_key: str = EXPECTED_API_KEY, jwt_algorithm: str = "HS256"):

        self._expected_key = expected_key
        self._jwt_algorithm = jwt_algorithm

    def create_auth_token(self, user_id: str = "llm-client-internal") -> str:
        """Internal method to generate a signed JWT."""
        try:
            payload = {
                'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24),
                'iat': datetime.datetime.utcnow(),
                'sub': user_id
            }
            return jwt.encode(
                payload,
                self._expected_key,
                algorithm=self._jwt_algorithm
            )
        except Exception as e:
            raise RuntimeError(f"Error creating JWT internally: {e}")

    @classmethod
    def _initialize_llm(cls) -> Llama:
        if cls._llm_instance is not None:
            return cls._llm_instance

        if not os.path.exists(MODEL_PATH):
            raise InitializationError(f"Model not found at expected path: {MODEL_PATH}")

        try:
            cls._llm_instance = Llama(
                model_path=MODEL_PATH,
                n_ctx=C_WIN,
                verbose=False
            )
            # print("--- LLM Initialized Successfully ---")
            return cls._llm_instance
        except Exception as e:
            raise InitializationError(f"Failed to initialize LLM: {e}")

    def _decode_auth_token(self, auth_token: str) -> Dict[str, Any]:
        """
        Decodes and verifies the JWT against the internal secret key.

        :raises: AuthenticationError on any JWT validation failure.
        """
        try:
            payload = jwt.decode(
                auth_token,
                self._expected_key,
                algorithms=[self._jwt_algorithm]
            )
            return payload
        except jwt.PyJWTError as e:
            raise AuthenticationError(f"Invalid JWT provided: {e}")

    def _parse_json_response(self, response_text: str) -> Dict[str, Any]:
        """Handles strict and relaxed JSON parsing."""
        try:
            return json.loads(response_text)
        except json.JSONDecodeError:
            if response_text.startswith("```json"):
                cleaned_text = response_text.replace("```json", "", 1).strip()
                if cleaned_text.endswith("```"):
                    cleaned_text = cleaned_text[:-3].strip()
                try:
                    return json.loads(cleaned_text)
                except json.JSONDecodeError:
                    pass

            # print(f"Warning: LLM did not return valid JSON. Raw response: {response_text}", file=sys.stderr)
            return {"Error": "LLM response was not valid JSON", "RawResponse": response_text}

    def call_llm(self, prompt: str, auth_token: str) -> Dict[str, Any]:
        """
        The core logic: Authenticates (decodes JWT) and calls the LLM.
        """
        payload = self._decode_auth_token(auth_token)
        # print(f"Authentication Successful. Token subject: {payload.get('sub')}")

        try:
            llm = self._initialize_llm()
        except Exception as e:
            raise InitializationError(f"Service Error: Cannot load the LLM model. Details: {e}")

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
                max_tokens=C_WIN,
                repeat_penalty=1.1,
                top_p=0.9,
                top_k=40,
                temperature=0.03
            )
            response_text = response['choices'][0]['message']['content'].strip()
            return self._parse_json_response(response_text)
            # return response_text
        except Exception as e:
            raise LLMGenerationError(f"Error during LLM chat completion: {e}")



def ask_llm(prompt: str) -> Dict[str, Any]:
    """
    The public function signature. Accepts the prompt and the pre-generated JWT.

    :param prompt: The user's input content.
    :return: The JSON result from the LLM, or a structured error dictionary.
    """
    try:
        service = LLMService(expected_key=EXPECTED_API_KEY)
        auth_token = service.create_auth_token()
        return service.call_llm(prompt, auth_token)
    except AuthenticationError as e:
        return {"Error": str(e), "Code": 401}
    except (InitializationError, LLMGenerationError) as e:
        return {"Error": str(e), "Code": 500}
    except Exception as e:
        return {"Error": f"An unexpected critical error occurred: {e}", "Code": 500}
