# Last modified: 2026-11-09T06:30:57.684126+00:00
FROM demisto/python3:3.12.15.14069087


COPY requirements.txt .
RUN apk --update add --no-cache --virtual .build-dependencies \
    python3-dev \
    build-base \
    wget \
    git \
    libffi-dev \
    openssl-dev \
    zip \
    unzip \
    && pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir --no-deps "msgpack>=1.2.3" \
    && pip download --no-deps dxlclient \
    && unzip dxlclient-*.whl -d dxlclient_src \
    && echo "import msgpack as _msgpack; globals().update(_msgpack.__dict__); unpackb = lambda *a, **kw: _msgpack.unpackb(*a, **dict(kw, raw=True)); unpack = lambda *a, **kw: _msgpack.unpack(*a, **dict(kw, raw=True))" > dxlclient_src/dxlclient/msgpack_wrapper.py \
    && find dxlclient_src -name "*.py" -exec sed -i 's/import msgpack/import dxlclient.msgpack_wrapper as msgpack/g' {} + \
    && find dxlclient_src -name "*.py" -exec sed -i 's/from msgpack import/from dxlclient.msgpack_wrapper import/g' {} + \
    && cd dxlclient_src && zip -r ../dxlclient_patched.whl . \
    && cd .. \
    && pip install --force-reinstall --no-deps dxlclient_patched.whl \
    && rm -rf dxlclient_src dxlclient-*.whl dxlclient_patched.whl \
    && apk del .build-dependencies
