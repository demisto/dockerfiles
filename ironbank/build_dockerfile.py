import argparse
import os
from dockerfile_parse import DockerfileParser

from ironbank.utils import get_dockerfile_content, BaseImagesStore

from ironbank.constants import DockerfileMetadata, DockerfileSections


class DockerfileIronBank:

    def __init__(self, docker_image_dir, output_path):
        self.docker_image_dir = docker_image_dir
        self.docker_image_name = os.path.basename(self.docker_image_dir)
        self.output_path = output_path
        self.base_images_repo = BaseImagesStore()

    def build(self):
        src_dockerfile_content = get_dockerfile_content(os.path.join(self.docker_image_dir, DockerfileMetadata.FILENAME))
        src_dockerfile_parser = DockerfileParser(os.path.join(self.docker_image_dir, DockerfileMetadata.FILENAME))
        dst_dockerfile = os.path.join(self.output_path, DockerfileMetadata.FILENAME)
        base_image, base_tag = src_dockerfile_parser.baseimage.split(":")
        print(f"Converting {os.path.join(self.docker_image_dir, DockerfileMetadata.FILENAME)} into {dst_dockerfile}")
        with open(dst_dockerfile, "w") as f:
            f.write(DockerfileSections.HEADER.format(self.base_images_repo.get_inventory()[base_image][0], base_tag))
            f.write(DockerfileSections.FILE_BLANK_LINE)
            f.write(DockerfileSections.COPY_REQS_TXT)
            f.write(DockerfileSections.FILE_BLANK_LINE)
            f.write(DockerfileSections.DNF_UPDATE_BASIC_PY.format(self.base_images_repo.get_inventory()[base_image][1]))
            f.write(DockerfileSections.FILE_BLANK_LINE)
            f.write(DockerfileSections.FOOTER)
            f.close()

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
    dockerfile_ironbank = DockerfileIronBank(docker_image_dir, output_path)
    dockerfile_ironbank.build()
    dockerfile_ironbank.dump()


if __name__ == '__main__':
    main()
