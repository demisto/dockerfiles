pip freeze | grep -E '^pymispwarninglists==' | grep -o -E '[0-9]+\.[0-9]+(\.[0-9]+)?'
