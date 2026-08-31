import sklearn
import pandas
import numpy
import nltk
import dill
import networkx
from bs4 import BeautifulSoup
from nltk.corpus import stopwords, wordnet

import os
assert int(os.environ['OPENBLAS_NUM_THREADS']) == 1

# A failed nltk.download() at build time used to leave /ml/nltk_data empty and still
# ship (XSUP-75716). nltk.data.find() only checks that a path exists, so a partial
# extraction that creates empty directories would pass it. Load the corpora for real
# instead, from the local NLTK_DATA only, so both cases fail the build.
assert stopwords.words('english')
assert wordnet.synsets('dog')

# Exercise the code path that actually broke for users of FindEmailCampaign.
assert nltk.tokenize.sent_tokenize('Hello there. General Kenobi.') == [
    'Hello there.', 'General Kenobi.']

print('All packages were imported successfully and NLTK data is available')
