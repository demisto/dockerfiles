Local deployment

This deployment creates docker containers for:
- Quadra service (name: quadra) with Titaniam Panther service running on port 8080
- MySQL (name: db) with MySQL running on port 3306


Prerequsites

* Install Docker: https://docs.docker.com/get-docker/
* Pull Quadra service from Demisto docker registry: docker pull demisto/quadra.
  (this will pull latest revision of Quadra service. You can also pull specific
   version: docker pull demisto/quadra:1.0.0).

Launch

Version of Panther service is configured in .env file. 
Add to the .env file following variables:

MYSQL_DATABASE=add_db_name_here
MYSQL_USER=add_username_here
MYSQL_PASSWORD=add_password_here

Replace each value with real database name, user name, and password.

Execute:

docker-compose up -d

Access Quadra Service

http://localhost:8080


Stop the services

In the docker directory:

docker-compose down


Useful commands

Logs

# Panther logs
docker-compose logs -f quadra

# MySQL logs
docker-compose logs -f db


Connect to a docker container

docker exec -it "quadra" /bin/bash

Remove all the docker containers and images

docker rm -vf $(docker ps -a -q)
docker rmi -f $(docker images -a -q)
