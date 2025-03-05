#!/bin/bash
DOCKER_IMAGE_NAME="cursecatcher"
docker run -d -it --env-file .env --name $DOCKER_IMAGE_NAME-$(date -u +"%Y-%m-%d") $DOCKER_IMAGE_NAME bash
docker ps -a