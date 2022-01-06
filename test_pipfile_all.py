from pathlib import Path

from test_pipfile_lock import DockerFileValidator

folders = tuple(path for path in Path('docker').glob('*') if path.is_dir())
for folder in folders:
    validator = DockerFileValidator(folder.absolute())
    try:
        validator.validate()  # raises on error
        print('OK', folder)
    except (ValueError, AssertionError, NotImplementedError) as e:  # todo change exception type
        print('INVALID', folder, str(e).replace("\n", "\t"))
