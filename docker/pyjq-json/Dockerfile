FROM demisto/python3-deb:3.9.6.22912

RUN apt-get update && apt-get install build-essential flex bison libtool make automake autoconf -y

RUN pip install --no-cache-dir --upgrade pip

RUN pip install --no-cache-dir --upgrade pyjq