# Demisto-SDK docker

Allows running demisto-sdk commands from within a docker container.

You can use this image to run demisto-sdk commands locally, or as part of a CI/CD process.

## The Content Repository

To use the Demisto-SDK, make sure you have a content-like repository with Cortex XSOAR content, in a structure that matches the official [XSOAR Content repo](https://github.com/demisto/content).
 
Such a repository may be generated using the following [template](https://github.com/demisto/content-external-template)

## Mounts

We use volume mount in our environment to run on local content repository.
Please note that there's a performance issue with mount on MacOS and Windows.
You can solve the performance issue by running on Linux/Windows WSL2 or by cloning your repository to the `/content` directory inside the container.

## Examples

(All examples use Cortex XSOAR's official [content repository](https://github.com/demisto/content)).

### Validate command
for more information about the validate command, please refer to its [documentation](https://github.com/demisto/demisto-sdk/blob/master/demisto_sdk/commands/validate/README.md) on the [demisto-sdk repo](https://github.com/demisto/demisto-sdk).
```sh
docker run -it --rm --mount type=bind,source="$(pwd)",target=/content demisto/demisto-sdk:<tag> demisto-sdk validate -i Packs/ipinfo/Integrations/ipinfo_v2
```

#### Breaking down command arguments

- docker run  
    Creates a container (if one does not exist) and runs the following command inside it
- -it  
    Keep the stdin open and tty
- --rm  
    Removes the docker container when done (ommit this part to re-use the container in the future)
- --mount type=bind,source="$(pwd)",target=/content  
    Connects the pwd (assuming you're in content) to the container's content directory
- demisto/demisto-sdk:\<tag> (Replace the tag with locked version)  
    The docker image name  
- demisto-sdk validate -i Packs/ipinfo/Integrations/ipinfo_v2
    The demisto-sdk command to be run inside the container

### Lint command

To run the `lint` command, connect the docker daemon (docker inside a docker), as lint itself is run inside a docker container. 

```sh
docker run -it --rm --mount type=bind,source="$(pwd)",target=/content --mount source=/var/run/docker.sock,target=/var/run/docker.sock,type=bind jochman/demisto-sdk <demisto-sdk-command>
```

#### The mount park

- --mount source=/var/run/docker.sock,target=/var/run/docker.sock,type=bind  
    Mounts the docker deamon container, to allow using docker commands from within a docker container.
