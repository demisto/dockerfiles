from pathlib import Path

from test_pipfile_lock import DockerFileValidator

for folder in (path for path in Path('docker').glob('*') if path.is_dir()):
    validator = DockerFileValidator(folder.absolute())
    try:
        validator.validate()  # raises on error
        print('OK', folder)
    except (ValueError, AssertionError, NotImplementedError) as e:  # todo change exception type
        print('INVALID', folder, str(e).replace("\n", "\t"))
