# Demisto-SDK docker

Run demisto-sdk commands from within a docker.

You can use this image to run validations locally on your work environment or inside your ci.

## The Content Repository

To use the Demisto-SDK you should have a content-like repository (or use the official [content repository](https://github.com/demisto/content)).
You can generate one from this [template](https://github.com/demisto/content-external-template)

## Mounts

We use volume mount in our environment to run on local content repository.
Please note that there's a performance issue with mount on MacOS and Windows.
You can solve the performance issue by running on Linux/Windows WSL2 or by cloning your repository to the `/content` directory inside the container.

## Examples

(All examples from the [content](https://github.com/demisto/content) repository).

### Validate command

```sh
docker run -it --rm --mount type=bind,source="$(pwd)",target=/content demisto/demisto-sdk:<tag> demisto-sdk validate -i Packs/ipinfo/Integrations/ipinfo_v2
```

#### Break down the command

- docker run  
    Creates a container and run a command
- -it  
    Keep the stdin open and tty
- --rm  
    Removes the docker container when done (Remove if you want to reuse the container)
- --mount type=bind,source="$(pwd)",target=/content  
    Connect the pwd (assuming you're in content) to the content directory in the container
- demisto/demisto-sdk:\<tag> (Replace the tag with locked version)  
    The docker image name  
- demisto-sdk validate -i Packs/ipinfo/Integrations/ipinfo_v2
    The command to run

### Lint command

If you want to run the `lint` command, you must connect the docker daemon (docker in docker)

```sh
docker run -it --rm --mount type=bind,source="$(pwd)",target=/content --mount source=/var/run/docker.sock,target=/var/run/docker.sock,type=bind jochman/demisto-sdk <demisto-sdk-command>
```

#### The mount park

- --mount source=/var/run/docker.sock,target=/var/run/docker.sock,type=bind  
    Mount the docker daemon in container to the outside (docker in docker)
