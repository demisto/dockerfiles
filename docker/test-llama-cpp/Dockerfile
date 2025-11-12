FROM demisto/python3-deb:3.12.12.5735221
WORKDIR /app
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    curl \
    procps \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

ENV MODEL_FILENAME="Meta-Llama-3.1-8B-Instruct-Q4_K_M.gguf"
ENV LLAMA_MODEL_PATH="/app/models/${MODEL_FILENAME}"
MODEL_DOWNLOAD_URL="https://huggingface.co/bartowski/Meta-Llama-3.1-8B-Instruct-GGUF/resolve/main/Meta-Llama-3.1-8B-Instruct-Q4_K_M.gguf"

RUN mkdir -p /app/models
RUN echo "Downloading Llama model from ${MODEL_DOWNLOAD_URL}" \
    && curl -L "${MODEL_DOWNLOAD_URL}" -o "${LLAMA_MODEL_PATH}" \
    && echo "Download complete."

#COPY "model/${MODEL_FILENAME}" "${LLAMA_MODEL_PATH}"