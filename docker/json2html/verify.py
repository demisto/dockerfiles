from json2html import *
input: dict = {
        "name": "json2html",
        "description": "content"
}
result: str = '<table border="1"><tr><th>name</th><td>json2html</td></tr><tr><th>description</th><td>content</td></tr></table>'
assert json2html.convert(json=input) == result