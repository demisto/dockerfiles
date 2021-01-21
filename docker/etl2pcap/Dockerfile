FROM demisto/python3:3.9.1.14969

RUN apk add git

RUN git config --global http.sslVerify false

RUN git clone https://github.com/aaptel/etl2pcap

RUN mkdir /var/opt/etl

RUN mv etl2pcap/* /var/opt/etl