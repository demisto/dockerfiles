FROM demisto/python3-deb:3.10.11.61265
RUN apt-get update && apt-get upgrade -y && apt-get -t bullseye-backports install gcc g++ wget git pkg-config \
make autoconf automake libtool libpng-dev libjpeg-dev libtiff5-dev zlib1g-dev libleptonica-dev libicu-dev libpango1.0-dev liblept5 -y \
&& mkdir /build && cd /build && git clone --depth 1 https://github.com/tesseract-ocr/tesseract.git \
&& cd tesseract && ./autogen.sh && ./configure && gmake && make install && ldconfig \
&& apt-get -t bullseye-backports install -y --no-install-recommends imagemagick file \
&& apt-get purge -y --auto-remove gcc g++ pkg-config make autoconf automake libtool libpng-dev \
libjpeg-dev libtiff5-dev zlib1g-dev libleptonica-dev libicu-dev libpango1.0-dev \
&& rm -rf /var/lib/apt/lists/* \
&& git clone https://github.com/zdenop/tessdata_downloader.git \
&& cd tessdata_downloader \
&& for lang in  eng ara chi_sim chi_sim_vert chi_tra chi_tra_vert deu fra heb ita jpn jpn_vert pol por rus spa swe tur ; \
do python tessdata_downloader.py -o /usr/local/share/tessdata/ -l $lang; done \ 
&& rm -rf /build \
&& tesseract --version --list-langs
