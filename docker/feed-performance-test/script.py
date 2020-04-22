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
        fake = Faker()
        fake.add_provider(internet)
        fake.add_provider(date_time)
        soFar = 0
        total = 2000000
        while len(generated_set) != total:
            indicator, csv_line = generate_indicator(fake, generated_type)
            if indicator in generated_set:
                continue
            generated_set.add(indicator)
            writer.writerow(csv_line)
            soFar += 1
            if (soFar % 10000 == 0):
                print(f"Finished {soFar} out of {total}")

    print("Finished" + filename)


generate_file('ips.csv', 'IP')
generate_file('domains.csv', 'Domain')
generate_file('hashes.csv', 'MD5')
