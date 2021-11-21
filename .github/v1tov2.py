import yaml

with open('/Users/ierukhimovic/dev/demisto/dockerfiles/.dependabot/config.yml') as f:
    config_yml = yaml.safe_load(f)

print(config_yml)
v2_config = {}
v2_config['version'] = 2
v2_config['updates'] = []
for update in config_yml['update_configs']:
    print(update)
    new_update = {'package-ecosystem': update['package_manager'] if update['package_manager'] != 'python' else 'pip',
                  'directory': update['directory'],
                  'schedule': {'interval': 'daily'}}
    v2_config['updates'].append(new_update)
with open('/Users/ierukhimovic/dev/demisto/dockerfiles/.github/dependabot.yml', 'w') as f:
    yaml.dump(v2_config, f)