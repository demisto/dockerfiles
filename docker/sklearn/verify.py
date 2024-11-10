import sklearn
import pandas
import numpy
import nltk
import dill
import networkx
from bs4 import BeautifulSoup

import os
import multiprocessing
assert os.environ['OPENBLAS_NUM_THREADS'] == 1, f"{os.environ['OPENBLAS_NUM_THREADS']=}"
assert os.environ['OMP_NUM_THREADS'] == multiprocessing.cpu_count(), f"{os.environ['OMP_NUM_THREADS']=}, {multiprocessing.cpu_count()=}"

print('All packages were imported successfully')