import torch.nn as nn
import os
import fasttext
import sklearn
import numpy
import pandas
import nltk
import lime
import tabulate
from Crypto.Hash import SHA256
import spacy
nlp = spacy.load('en_core_web_sm', disable=['tagger', 'parser', 'ner', 'textcat'])
doc = nlp('tokenize this sentence')
import demisto_ml
import catboost
import eli5
import langdetect
import onnx

def verify_stat(filename):
    res = os.stat(filename)
    assert res.st_uid == 4000
    assert res.st_gid == 4000
    assert oct(res.st_mode)[-3:] == '775'


verify_stat('/ml/encrypted_model.b')
verify_stat('/ml/nltk_data')
verify_stat('/ml/oob_evaluation.txt')


print('All package imported succesfully')







