# Use this script to load ironbank docker locally.
# the first argument is the docker image name,
# the second argument is the zip file created in ironbank build process from the artifacts of the job 'create-tar' ,
# the third argument is the output path for creating the docker tar file.
# example for use the script: docker_test.sh ironbank/python:1.0.0.0  ~/Downloads/artifacts.zip ~/ironbank_dockers/python.tar

IMAGE_NAME="$1"
DOCKER_ZIP="$2"
OUTPUT_TAR="$3"

echo "=============================="
echo "IMAGE_NAME: $IMAGE_NAME"
echo "DOCKER_ZIP: $DOCKER_ZIP"
echo "OUTPUT_DIR: $OUTPUT_TAR"
echo "==============================\n\n"

DOCKER_ZIP_DIR="$(dirname "${DOCKER_ZIP}")" ; FILE="$(basename "${DOCKER_ZIP}")"

echo "=============== Extract $FILE file ==============="
unzip_output=`unzip "$DOCKER_ZIP" -d $DOCKER_ZIP_DIR`
unzip_output=`echo $unzip_output | tail -1`
tar_file=`echo $unzip_output | sed 's/.*inflating: //' | xargs`


echo "\n=============== Extract the tar file ==============="
cd $DOCKER_ZIP_DIR
mkdir tar_files
tar -xvf $tar_file -C $DOCKER_ZIP_DIR/tar_files


echo "\n=============== Update manifest.json ==============="
cd tar_files
manifest_contents=`cat manifest.json`
rm manifest.json
echo $manifest_contents > manifest.json
cat <<< $(jq '.[0].RepoTags = ["'"$IMAGE_NAME"'"]' <<<"$jsonStr" manifest.json) > manifest.json


echo "\n=============== Creating docker tar file ==============="
pwd
sudo tar cvf $OUTPUT_TAR .


echo "\n=============== Load the docker image ==============="
docker load -i $OUTPUT_TAR

echo "\n=============== done ==============="