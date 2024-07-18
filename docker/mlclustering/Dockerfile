FROM devdemisto/python3-9-deb:3.9.16.103723

#COPY requirements.txt .
COPY environment.yml .
ADD https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh minicondainstall.sh
RUN chmod +x minicondainstall.sh && ./minicondainstall.sh -b -u -p ~/miniconda3
ENV PATH=/miniconda3/bin:${PATH}
RUN conda --version \
&& apt-get update \
&& apt-get install -y --no-install-recommends pipenv build-essential \
  gcc \
  python3-dev gfortran wget git g++ pkg-config libhdf5-dev
#RUN pip install -r requirements.txt
#RUN pip install --no-binary :all: hdbscan==0.8.27
RUN conda init && conda env create -f environment.yml && conda activate clusteringenv \
&& apt-get purge -y --auto-remove gcc pipenv \
  python3-dev gfortran wget git g++ pkg-config libhdf5-dev && rm -rf minicondainstall.sh
