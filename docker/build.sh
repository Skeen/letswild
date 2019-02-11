#!/bin/bash

VERSION_NUMBER=0.0.1.0
TAG_PREFIX=
IMAGE=letswild
IMAGE_PATH=${TAG_PREFIX}skeen/${IMAGE}

cd "$(dirname "$0")"

echo "Building docker container"
docker build -t ${IMAGE_PATH}:latest -f Dockerfile ..

function tag {
    docker tag ${IMAGE_PATH}:latest ${IMAGE_PATH}:$1
    docker push ${IMAGE_PATH}:$1
}

IFS='.' read -ra VER <<< "${VERSION_NUMBER}"
VER_SO_FAR="${VER[0]}"
VER=("${VER[@]:1}")
tag "$VER_SO_FAR"
for i in "${VER[@]}"; do
    VER_SO_FAR=${VER_SO_FAR}.${i}
    tag "$VER_SO_FAR"
done
