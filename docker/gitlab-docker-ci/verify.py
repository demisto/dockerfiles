import subprocess

expected_versions = ["2.7.18", "3.9.16", "3.8.15", "3.10.13", "3.11.0", "3.12.11", "3.13.7"]

def get_installed_pyenv_versions():
    result = subprocess.run(['pyenv', 'versions'], stdout=subprocess.PIPE, text=True)
    installed_versions = []
    for line in result.stdout.splitlines():
        cleaned_line = line.strip().replace('*', '').strip()

        version_part = cleaned_line.split(' ')[0]
        installed_versions.append(version_part)
    return installed_versions

def verify_versions():
    installed_versions = get_installed_pyenv_versions()
    missing_versions = [version for version in expected_versions if version not in installed_versions]
    
    if not missing_versions:
        print("All expected versions are installed.")
    else:
        print(f"Missing versions: {missing_versions}")

# Call the function to perform the check
verify_versions()