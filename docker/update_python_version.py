import os
import sys
import subprocess
from git import Repo
from git.exc import GitCommandError

def update_python_version(filepath, old_version, new_version):
    """Update Python version in a given file."""
    with open(filepath, "r") as f:
        content = f.read()

    updated_content = content.replace(old_version, new_version)

    with open(filepath, "w") as f:
        f.write(updated_content)

def run_command(command, cwd=None):
    """Run a shell command and return its output."""
    try:
        result = subprocess.run(command, shell=True, cwd=cwd, check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"Error running command: {command}\n{e.stderr}")
        raise

def get_branches_by_author(repo_path, author):
    """Retrieve branches with the latest commit authored by the specified user."""
    branches = []
    command = "git for-each-ref --format='%(refname:short)' refs/remotes/origin/"
    output = run_command(command, cwd=repo_path)
    
    
    for branch in output.splitlines():
        branch_name = branch.replace("origin/", "")
        if branch_name in ("master", "origin"):
            continue
        
        # Check the author of the latest commit on the branch
        log_command = f"git log -1 --format='%an' origin/{branch_name}"
        branch_author = run_command(log_command, cwd=repo_path).strip("'")
        if branch_author == author:
            branches.append(branch_name)

    return branches

def main():
    # repo_path = input("Enter the path to your local DockerFiles repository (leave empty for current directory): ").strip()

    # if not repo_path:
    repo_path = os.getcwd()

    if not os.path.exists(repo_path):
        print(f"The specified repository path does not exist: {repo_path}")
        sys.exit(1)

    repo = Repo(repo_path)

    if repo.bare:
        print("The specified repository is not a valid Git repository.")
        sys.exit(1)

    # Fetch all branches opened by "auto dockerfiles update"
    repo.remotes.origin.fetch()
    branches = get_branches_by_author(repo_path, "auto dockerfiles update")

    print(f"{branches=}, \n{len(branches)=}")
    input("Continue?")
    for branch_name in branches:

        try:
            print(f"Checking out branch {branch_name}")
            repo.git.checkout(branch_name)
            merge_base = repo.git.merge_base("master", branch_name)
        except GitCommandError as e:
            print(f"Error checking out branch {branch_name}: {e}")
            continue
        except Exception as e:
            print(f"Error updating Dockerfile: {e}")
            raise
        
        # Check if Dockerfile was changed
        diff_files = repo.git.diff('--name-only', merge_base, branch_name).splitlines()
        print(f"{diff_files=}")
        input(f"Continue?")
        
        try:
            for file in diff_files:
                if file.endswith("Dockerfile"):
                    root = file.rsplit("/", 1)[0]
                    pipfile_path = os.path.join(root, "Pipfile")
                    pipfile_lock_path = os.path.join(root, "Pipfile.lock")
                    pyproject_path = os.path.join(root, "pyproject.toml")
                    poetry_lock_path = os.path.join(root, "poetry.lock")

                    # Update Pipfile or pyproject.toml
                    if os.path.exists(pipfile_path):
                        update_python_version(pipfile_path, 'python_version = "3.11"', 'python_version = "3.12"')
                        lock_command = "pipenv lock"
                        lock_file = pipfile_lock_path
                    elif os.path.exists(pyproject_path):
                        update_python_version(pyproject_path, 'python = "~3.11"', 'python = "~3.12"')
                        lock_command = "poetry lock"
                        lock_file = poetry_lock_path
                    else:
                        print(f"No Pipfile or pyproject.toml found in {root}, skipping.")
                        continue

                    # Run lock command
                    run_command(lock_command, cwd=root)

                    # Review changes
                    review = input(f"Did you review the changes in {lock_file}? (y/n): ").strip().lower()

                    if review in ["y", "yes"]:
                        repo.git.add([pipfile_path if os.path.exists(pipfile_path) else pyproject_path, lock_file])
                        repo.git.commit(m="Update Python version to 3.12")
                        repo.git.push()
                    else:
                        review_2 = input(f"You sure? (y/n): ").strip().lower()
                        if review_2 in ["y", "yes"]:
                            repo.git.checkout([pipfile_path if os.path.exists(pipfile_path) else pyproject_path])
                        else:
                            repo.git.add([pipfile_path if os.path.exists(pipfile_path) else pyproject_path, lock_file])
                            repo.git.commit(m="Update Python version to 3.12")
                            repo.git.push()
        except Exception as e:
            print(f"Error!!!\n{e}")
            r = input("Continue after error? (y/n): ")
            if r in ["y", "yes"]:
                pass
            else:
                raise e

if __name__ == "__main__":
    main()
