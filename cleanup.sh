#!/bin/bash
rm -rf env
rm -rf static/*
DOCKER_IMAGE_NAME="cursecatcher"
docker ps -a | grep $DOCKER_IMAGE_NAME|awk '{print $1}' | xargs docker stop $i
docker ps -a | grep $DOCKER_IMAGE_NAME|awk '{print $1}' | xargs docker rm $i