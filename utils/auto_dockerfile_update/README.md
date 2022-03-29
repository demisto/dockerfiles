## Auto docker file update
The auto update dockerfiles flow includes:
 - github actions flow files:
   - create-update-dockerfiles-PR.yml
   - update-external-base-images.yml
   - update-internal-base-images.yml
 - python scripts:
   - get_dockerfiles.py
   - get_latest_tag.py
   - update_dockerfiles.py
 
### Github actions files
- #### Update external base images
   For each docker file with external base image.
  
   external base image - images that are not from the demisto's dockerfiles repository:
  
  1. Check for new minor or micro updates, for example ```alpine-3.14``` will search for new tags from the format ```alpine-3.X```.
  Note: for ```alpine-3.14-python-3.9.1``` the script will update only if all the versions are equal or greater.
  2. If there is a new image, or the latest image was updated creates a new branch and update the docker file with the latest tag and date.
   
- #### Update internal base images
   For each docker file with internal base image.
  
   internal base image - images that are from the demisto's dockerfiles repository:
  
  1. Get all the dockerfiles that are used as based image on other dockefiles.
  2. For each docker file get the latest tag from the docker registry   
  3. If there is a new tag, updates all the dependant images in batches. For each batch crates a branch and push the relevant updates.
   
- #### Create update dockerfiles PR
   Creates pull request for all the branches created by the previous actions.
   
### General flow

1. The *Update external base images* actions runs once a day.
2. Creates PR for each file that was updated.
3. Once PR is merged, runs the *Update internal base images* action.
4. Creates PR for each batch created by the previous step.
5. Once PR is merged, go to step 3 until there are no more files to update.

![Example flow](flow_diagram.png "Example flow")