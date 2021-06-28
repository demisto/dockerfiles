import nltk
import os

print('All package imported succesfully')

assert os.path.isdir('/ml/nltk_data')
assert os.path.isdir('/ml/distilbert-base-uncased_tokenizer')


def verify_stat(filename):
    res = os.stat(filename)
    assert res.st_uid == 4000
    assert res.st_gid == 4000
    assert oct(res.st_mode)[-3:] == '775'


verify_stat('/ml/distilbert-base-uncased_tokenizer')
verify_stat('/ml/nltk_data')
verify_stat('/ml/distilbert-base-uncased.onnx')
verify_stat('/ml/glove_100_top_20k.p')

print('All files verified')








