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

RUN mkdir -p /app/models

COPY "${MODEL_FILENAME}" "${LLAMA_MODEL_PATH}"