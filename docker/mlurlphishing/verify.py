import numpy as np
import pandas as pd
import sklearn
from bs4 import BeautifulSoup
import cv2 as cv
import tldextract
import dill
import catboost
from PIL import Image
from cv2 import cv2
import urllib3
import certifi

with open('/model/model_docker.pkl', 'rb') as f:
    model = dill.load(f)  # guardrails-disable-line
    data = pd.DataFrame(dict.fromkeys(('html', 'name', 'image', 'url'), ['data']*3))
    model.predict(data)

