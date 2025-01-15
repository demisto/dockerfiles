import subprocess
import sys

def verify_python_version(version):
    """ Verify if provided python version is correctly installed. """
    try:
        subprocess.run([f"/root/.pyenv/shims/python{version}", "-c", "import sys; print(sys.version)"], check=True, text=True, stdout=subprocess.PIPE)
    except subprocess.CalledProcessError:
        sys.exit(1)

def main():
    versions = ["2.7.18", "3.9.16", "3.8.15", "3.10.13", "3.10.13", "3.11.0", "3.12.0"]
    for ver in versions:
        verify_python_version(ver)


if __name__ == "__main__":
    main()