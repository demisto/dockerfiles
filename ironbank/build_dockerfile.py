import argparse
import os
from dockerfile_parse import DockerfileParser

from ironbank.utils import get_dockerfile_content, BaseImagesStore, get_base_image_from_dockerfile, \
    get_last_image_tag_ironbank

from ironbank.constants import DockerfileMetadata, DockerfileSections


class DockerfileIronbank:

    def __init__(self, docker_image_dir, output_path):
        self.docker_image_dir = docker_image_dir
        self.docker_image_name = os.path.basename(self.docker_image_dir)
        self.output_path = output_path
        self.base_images_repo = BaseImagesStore()

    def build(self):
        src_dockerfile = os.path.join(self.docker_image_dir, DockerfileMetadata.FILENAME)
        dst_dockerfile = os.path.join(self.output_path, DockerfileMetadata.FILENAME)
        base_image, base_image_tag = get_base_image_from_dockerfile(src_dockerfile)
        ironbank_base_image = self.base_images_repo.get_inventory()[base_image][0]
        ironbank_base_image_tag = get_last_image_tag_ironbank(ironbank_base_image)
        print(f"Converting {os.path.join(self.docker_image_dir, DockerfileMetadata.FILENAME)} into {dst_dockerfile}")
        print(f"Docker Hub base image tag is {0} vs. Ironbank base image tag {2}".
              format(base_image_tag + ":" + base_image_tag, ironbank_base_image + ":" + ironbank_base_image_tag))

        with open(dst_dockerfile, "w") as fp:
            fp.write(DockerfileSections.HEADER.format(ironbank_base_image, ironbank_base_image_tag))
            fp.write(DockerfileSections.FILE_BLANK_LINE)
            fp.write(DockerfileSections.COPY_REQS_TXT)
            fp.write(DockerfileSections.FILE_BLANK_LINE)
            fp.write(DockerfileSections.USER_ROOT)
            fp.write(DockerfileSections.FILE_BLANK_LINE)
            fp.write(DockerfileSections.DNF_UPDATE_BASIC_PY.format(self.base_images_repo.get_inventory()[base_image][1]))
            fp.write(DockerfileSections.FILE_BLANK_LINE)
            fp.write(DockerfileSections.DOCKER_ENV)
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
