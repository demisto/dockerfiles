# This is a py-tools image that is based on debian linux
FROM demisto/python3-deb:3.10.8.36615

COPY requirements.txt .

#ADD pyproject.toml .
#ADD poetry.lock .

#ENV PATH /root/.local/bin:$PATH

#RUN apt-get update && apt-get install -y curl build-essential wget git libffi-dev \
#    && curl -sSL https://install.python-poetry.org | python3 - \
#    && poetry config virtualenvs.create false \
#    && poetry install \
#    && pip uninstall -y pcodedmp \
#    && apt-get purge -y --auto-remove build-essential

RUN apt-get update && apt-get install -y --no-install-recommends build-essential wget git libffi-dev \
    && pip install --no-cache-dir -r requirements.txt \
    && apt-get purge -y --auto-remove build-essential \
    && pip uninstall -y pcodedmp