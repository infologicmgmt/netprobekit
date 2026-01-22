#Filename: Makefile
#Author: Michael Moscovitch
#Assistant: Jules
#Date: 2026/01/10
#Description: Makefile
#Copyright (c) 2026 Michael Moscovitch
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
.PHONY: all install install-requirements clean build-docker

REQUIREMENTS=requirements.txt

all: install install-requirements

install:
	pip install -e .

install-requirements:
	pip install -r $(REQUIREMENTS)

clean:
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete

build-docker:
	docker build -t netprobe .
