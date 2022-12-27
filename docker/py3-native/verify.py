# make sure regex is working cause in new versions there are problems
import regex
pattern = regex.Regex('\\\\d\\+', flags=regex.V0)
print('regex is good')

    
