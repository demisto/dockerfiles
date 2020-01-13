from faker import Faker
from faker.providers import internet, date_time
import csv

def generate_indicator(fake, indicator_type):
    fakes = {"IP": fake.ipv4(),
             "Domain": fake.pystr_format(string_format="?????#???????###.com",
                                         letters="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"),
             "URL": fake.pystr_format(string_format="https://?????#???????###.com",
                                      letters="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"),
             "MD5": fake.md5()}
    value = fakes[indicator_type]

    return value, [value, fake.lexify(text="???? ?????? ?? ?????", letters="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"), fake.date_this_century()]

def generate_file(filename, generated_type):
    print("Generating " + filename)
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile, delimiter=',',
                            quotechar='"', quoting=csv.QUOTE_MINIMAL)
        generated_set = set()
        csv_lines = []
        fake = Faker()
        fake.add_provider(internet)
        fake.add_provider(date_time)
        while len(generated_set) != 450000:
            indicator, csv_line = generate_indicator(fake, generated_type)
            if indicator in generated_set:
                continue
            generated_set.add(indicator)
            csv_lines.append(csv_line)

        for csv_line in csv_lines:
            writer.writerow(csv_line)
    print("Finished" + filename)


generate_file('ips.csv', 'IP')
generate_file('domains.csv', 'Domain')
generate_file('hashes.csv', 'MD5')
