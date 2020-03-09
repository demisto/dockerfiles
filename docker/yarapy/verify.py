import yara
import plyara

rule = yara.compile(source='rule foo: bar {strings: $a = "lmn" condition: $a}')
matches = rule.match(data='abcdefgjiklmnoprstuvwxyz')
parser = plyara.Plyara()
mylist = parser.parse_string('rule foo: bar {strings: $a = "lmn" condition: $a}')
print("all is good: {}".format(matches))
