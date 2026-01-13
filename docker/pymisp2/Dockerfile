# Last modified: 2026-01-13T12:12:41.082509+00:00

FROM demisto/python3:3.12.12.6663663

COPY requirements.txt .

RUN pip install --upgrade pip \
 && apk --update add --no-cache --virtual .build-dependencies python3-dev gcc linux-headers libc-dev libffi-dev\
 build-base wget git && pip install --no-cache-dir -r requirements.txt && apk del .build-dependencies && pip uninstall -y extract-msg\
 && pip uninstall -y pcodedmp \
 && sed -i -e '/^from extract_msg/d; s/msg_obj: MsgObj/msg_obj/g; s/msg_obj: MessageBase/msg_obj/g' /usr/local/lib/python3*/site-packages/pymisp/tools/emailobject.py