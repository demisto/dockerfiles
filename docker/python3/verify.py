import warnings
import dateparser
import tldextract
# set warnings to throw an error
warnings.simplefilter("error")
d = dateparser.parse('1 day')
extract = tldextract.TLDExtract(cache_file=False,suffix_list_urls=None)
t = extract('*test-test.com')
print("all is good managed to parse: {}".format(d))
