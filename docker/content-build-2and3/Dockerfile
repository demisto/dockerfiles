FROM devdemisto/content-build-2and3:2.0.0.2991

COPY requirements.txt ./requirements3.txt

RUN bash -i -c 'pyenv exec pip3 install --no-cache-dir -r requirements3.txt'
