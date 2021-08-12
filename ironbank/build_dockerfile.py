import argparse
import os

from ironbank.utils import BaseImagesStore, get_base_image_from_dockerfile, \
    get_last_image_tag_ironbank

from ironbank.constants import DockerfileMetadata, DockerfileSections, DEMISTO_REGISTRY_ROOT
from docker.image_latest_tag import get_latest_tag


class DockerfileIronbank:

    def __init__(self, docker_image_dir, output_path):
        self.docker_image_dir = docker_image_dir
        self.docker_image_name = os.path.basename(self.docker_image_dir)
        self.output_path = output_path
        self.base_images_repo = BaseImagesStore()
        self.dockerhub_image_uri = os.path.join('demisto', self.docker_image_name)
        self.ironbank_image_uri = os.path.join(DEMISTO_REGISTRY_ROOT, self.docker_image_name)
        self.image_tag = ''


    def build(self):
        src_dockerfile = os.path.join(self.docker_image_dir, DockerfileMetadata.FILENAME)
        dst_dockerfile = os.path.join(self.output_path, DockerfileMetadata.FILENAME)
        base_image, base_image_tag = get_base_image_from_dockerfile(src_dockerfile)
        ironbank_base_image = self.base_images_repo.get_inventory()[base_image][0]
        ironbank_base_image_tag = get_last_image_tag_ironbank(ironbank_base_image)
        print(f"Converting {os.path.join(self.docker_image_dir, DockerfileMetadata.FILENAME)} into {dst_dockerfile}")
        print(f"Docker Hub base image tag is {0} vs. Ironbank base image tag {2}".
              format(base_image_tag + ":" + base_image_tag, ironbank_base_image + ":" + ironbank_base_image_tag))
        self.image_tag = get_latest_tag(self.dockerhub_image_uri)


        with open(dst_dockerfile, "w") as fp:
            fp.write(DockerfileSections.HEADER.format(ironbank_base_image, ironbank_base_image_tag))
            fp.write(DockerfileSections.FILE_BLANK_LINE)
            fp.write(DockerfileSections.COPY_REQS_TXT)
            fp.write(DockerfileSections.FILE_BLANK_LINE)
            fp.write(DockerfileSections.MAKE_PIP_PKGS_DIR)
            fp.write(DockerfileSections.FILE_BLANK_LINE)
            fp.write(DockerfileSections.COPY_EVERYTHING_TO_PIP_PKGS)
            fp.write(DockerfileSections.FILE_BLANK_LINE)
            fp.write(DockerfileSections.USER_ROOT)
            fp.write(DockerfileSections.FILE_BLANK_LINE)
            fp.write(DockerfileSections.DNF_UPDATE_BASIC_PY.format(self.base_images_repo.get_inventory()[base_image][1]))
            fp.write(DockerfileSections.FILE_BLANK_LINE)
            fp.write(DockerfileSections.DOCKER_ENV_ORIGINAL.format(self.dockerhub_image_uri, self.image_tag))
            fp.write(DockerfileSections.FILE_BLANK_LINE)
            fp.write(DockerfileSections.DOCKER_ENV_IRON_BANK.format(self.ironbank_image_uri, self.image_tag))
            fp.write(DockerfileSections.FILE_BLANK_LINE)
            fp.write(DockerfileSections.FOOTER)
            fp.close()

    def dump(self):
        return


def args_handler():
    parser = argparse.ArgumentParser(
        description="Build Dockerfile for a given docker image, see: "
                    "https://repo1.dso.mil/dsop/dccscr/-/blob/master/hardening%20manifest/README.md")
    parser.add_argument('--docker_image_dir', help='The path to the docker image dir in the dockerfiles project',
                        required=True)
    parser.add_argument('--output_path', help='Full path of folder to output the hardening_manifest.yaml file',
                        required=True)
    return parser.parse_args()


def main():
    args = args_handler()
    docker_image_dir = args.docker_image_dir
    output_path = args.output_path

    print("Converting docker {0} to {1} ".format(docker_image_dir, output_path))
    dockerfile_ironbank = DockerfileIronbank(docker_image_dir, output_path)
    dockerfile_ironbank.build()
    dockerfile_ironbank.dump()


if __name__ == '__main__':
    main()
