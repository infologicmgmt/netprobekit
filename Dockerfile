#Filename: Dockerfile
#Author: Michael Moscovitch
#Assistant: Jules
#Date: 2026/01/10
#Description: Dockerfile
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
# Use an official Python runtime as a parent image
FROM python:3.11

# Set the working directory in the container
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    nmap \
    snmp \
    less \
    nano \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

# Copy the requirements files to the working directory
COPY requirements.txt .
COPY requirements-base.txt .

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy the project files to the working directory
COPY pyproject.toml .
COPY setup.py .
COPY netprobe ./netprobe
COPY scripts ./scripts

# Install Python dependencies
RUN pip install --no-cache-dir .

# Expose the port the app runs on
EXPOSE 8000

# Define the command to run the application
ENTRYPOINT ["/app/scripts/entrypoint.sh"]

