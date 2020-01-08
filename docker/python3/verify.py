import warnings
import dateparser

# set warnings to throw an error
warnings.simplefilter("error")
d = dateparser.parse('1 day')
print("all is good managed to parse: {}".format(d))
