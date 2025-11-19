FROM demisto/python3-deb:3.12.12.5735221
WORKDIR /app
RUN apt-get update \
    && apt-get upgrade -y  \
    && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    curl \
    procps \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

ENV MODEL_FILENAME="tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf"
ENV MODEL_PATH="/app/models/${MODEL_FILENAME}"

RUN mkdir -p /app/models

COPY "${MODEL_FILENAME}" "${MODEL_PATH}"

COPY run_llm.py .
