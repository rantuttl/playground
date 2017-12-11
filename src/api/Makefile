# Copyright 2017-2018 rantuttl All rights reserved.
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
REGISTRY=rtuttle

API_CONTAINER=$(REGISTRY)/api-build
API_NODE_CONTAINER=$(REGISTRY)/api-node-server
BIN_IMAGE_DIR=api-server
API_NODE_DIR=api_node
API_NODE_BIN_DIR=$(API_NODE_DIR)/filesystem/bin
VERSION=$(python2.7 setup.py --version 2>>/dev/null)
GIT_COMMIT=$(git rev-parse HEAD)
GIT_COMMIT_SHORT=$(git rev-parse --short HEAD)

UID=$(shell id -u)
SOURCE_DIR?=$(dir $(lastword $(MAKEFILE_LIST)))
SOURCE_DIR:=$(abspath $(SOURCE_DIR))

# Builds the API build container
# ---------------------------------------------------------------------------------------------------------------------------------
build-container:
	docker build -t $(API_CONTAINER) .

# API binary build only
build-binary:
	$(shell echo "API version:" $(VERSION) > version.txt)
	$(shell echo "Git revision:" $(GIT_COMMIT) >> version.txt)

        # run the script that builds the API from the api-server.spec file
	docker run --user $(UID) --rm \
		-v $(SOURCE_DIR):/code $(API_CONTAINER) \
		/code/pyi/run-pyinstaller.sh

	-mkdir -p ../dist/$(BIN_IMAGE_DIR)
	mv dist/$(BIN_IMAGE_DIR) ../dist/$(BIN_IMAGE_DIR)
	@echo "Build API Server"

# Build API binary straight into a container image
build-api-node-container: $(API_NODE_DIR)/Dockerfile
	cp ../dist/$(BIN_IMAGE_DIR)/* $(API_NODE_BIN_DIR)

	docker build -t $(API_NODE_CONTAINER) $(API_NODE_DIR)
