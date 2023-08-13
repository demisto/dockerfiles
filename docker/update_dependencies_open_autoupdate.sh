pr_list=$(gh pr list --state open --search 'autoupdate in:head'  --json headRefName)
git fetch
cwd=$(pwd)
echo $pr_list | jq -cr '.[].headRefName' | while read -r branch; do
  echo "Branch $branch"
  git checkout $branch
  name=$(git show --pretty="format:" --name-only)
  result="${name%/*}"
  echo found folder $result
  cd $result
  pipenv update certifi
  cd $cwd
  git commit -am "auto add update"
  exit
  git push
  exit
done