import yara

rule = yara.compile(source='rule foo: bar {strings: $a = "lmn" condition: $a}')
matches = rule.match(data='abcdefgjiklmnoprstuvwxyz')
print("all is good: " + matches)
