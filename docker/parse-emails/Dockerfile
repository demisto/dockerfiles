
FROM demisto/python3:3.12.11.4095827

# install system libraries
RUN apk --update add --no-cache libmagic openssl

# install production dependencies only
RUN apk --update add --no-cache --virtual .build-deps python3-dev build-base libffi-dev wget git \
    && apk del .build-deps

