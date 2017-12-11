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

default: all

all: containers binaries

binaries: api-binary
containers: build-container-python-if

container-build-base: build-container-base
container-build-python: build-container-python
container-build-api: build-api-container

# Globals definition (inplace)
# ---------------------------------------------------------------------------------------------------------------------------------
REGISTRY=rtuttle
DOCKERFILE_BUILDS_DIR=Dockerfiles

API_CONTAINER=$(REGISTRY)/api-build
API_DIR=api

BASE_BUILD_DIR=$(DOCKERFILE_BUILDS_DIR)/base
BASE_BUILD_CONTAINER=$(REGISTRY)/base-build

PY_BUILD_DIR=$(DOCKERFILE_BUILDS_DIR)/python
PY_BUILD_CONTAINER=$(REGISTRY)/python-build

# Base glibc alpine container build: reused by all containers
build-container-base:
	@echo "\033[92m\n\nBuilding base build container: $(BASE_BUILD_CONTAINER)\033[0m"
	@echo "-----------------------------------------------------------------"
	cd $(BASE_BUILD_DIR) && docker build -t $(BASE_BUILD_CONTAINER) .

# Build the glibc alpine container only if non existing
build-container-base-if:
	@echo "\033[92m\n\nChecking base build container existence: $(BASE_BUILD_CONTAINER)\033[0m"
	@echo "-----------------------------------------------------------------"
	docker images $(BASE_BUILD_CONTAINER):latest | grep "$(BASE_BUILD_CONTAINER)\s*latest" || $(MAKE) build-container-base

# Pybuild container builds the python compilation container reused by all python based parts
# ---------------------------------------------------------------------------------------------------------------------------------
# NOTE (rantuttl): Remove alpine 'base' container for now and just build from python:2.7.xx image
#build-container-python: build-container-base-if
build-container-python:
	@echo "\033[92m\n\nBuilding base python compilation container: $(PY_BUILD_CONTAINER)\033[0m"
	@echo "-----------------------------------------------------------------"
	cd $(PY_BUILD_DIR) && docker build -t $(PY_BUILD_CONTAINER) .

# Build the python build container only if non existing
build-container-python-if:
	@echo "\033[92m\n\nChecking base python compilation container existence: $(PY_BUILD_CONTAINER)\033[0m"
	@echo "-----------------------------------------------------------------"
	docker images $(PY_BUILD_CONTAINER):latest | grep "$(PY_BUILD_CONTAINER)\s*latest" || $(MAKE) build-container-python

# NOTE (rantuttl): Remove python 'base' container for now and just build from python:2.7.xx image
#api-container: build-container-python-if
api-container:
	@echo "\033[92m\n\nBuilding API container: $(API_CONTAINER)\033[0m"
	@echo "-----------------------------------------------------------------"
	$(MAKE) -C $(API_DIR) build-container

api-container-if:
	@echo "\033[92m\n\nChecking API container existence: $(API_CONTAINER)\033[0m"
	@echo "-----------------------------------------------------------------"
	docker images $(API_CONTAINER):latest | grep "$(API_CONTAINER)\s*latest" || $(MAKE) api-container

api-binary: api-container-if
	@echo "\033[92m\n\nCompiling API binaries\033[0m"
	@echo "-----------------------------------------------------------------"
	$(MAKE) -C $(API_DIR) build-binary

# Build api-node-ctlr container
build-api-container: api-binary
	@echo "\033[92m\n\nBuilding API runtime container\033[0m"
	@echo "-----------------------------------------------------------------"
	$(MAKE) -C $(API_DIR) build-api-node-container
