import tldextract
from pymispwarninglists import WarningLists

warning_lists = WarningLists()
assert len(warning_lists) > 0, "No warning lists were loaded"
assert warning_lists.search("8.8.8.8"), "Expected 8.8.8.8 to match a warning list"
offline_extract = tldextract.TLDExtract(suffix_list_urls=())
assert offline_extract("www.example.co.uk").suffix == "co.uk"

print("All is good. pymispwarninglists and tldextract imported successfully")
