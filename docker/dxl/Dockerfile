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
    && pip install --no-cache-dir -r requirements.txt \
    # dxlclient pins msgpack<1.0; keep its 0.x wire format on msgpack 1.x
    && pip install --no-cache-dir --no-deps "msgpack>=1.2.3" \
    && F="$(python -c 'import dxlclient.message as m; print(m.__file__)')" \
    && sed -i -e "s/msgpack.Packer()/msgpack.Packer(use_bin_type=False)/" \
        -e "s/msgpack.Unpacker(buf)/msgpack.Unpacker(buf, raw=True)/" "$F" \
    && grep -q "use_bin_type=False" "$F" && grep -q "raw=True" "$F" \
    && apk del .build-dependencies

