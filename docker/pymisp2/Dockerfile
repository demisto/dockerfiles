
FROM demisto/python3:3.10.13.80014

COPY requirements.txt .

RUN pip install --upgrade pip \
 && apk --update add --no-cache --virtual .build-dependencies python3-dev gcc linux-headers libc-dev libffi-dev\
 build-base wget git  \
    && sed -i '/extract-msg/d' requirements.txt && sed -i '/pcodedmp/d' requirements.txt  \
    && pip install --no-dependencies --no-cache-dir -r requirements.txt && apk del .build-dependencies \
 && sed -i -e '/from extract_msg import openMsg/d; /from extract_msg.message import Message as MsgObj/d; s/msg_obj: MsgObj/msg_obj/g' /usr/local/lib/python3*/site-packages/pymisp/tools/emailobject.py