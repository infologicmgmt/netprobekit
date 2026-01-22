"""
Filename: netprobe/config.py
Author: Michael Moscovitch
Assistant: Jules
Date: 2026/01/10
Copyright (c) 2026 Michael Moscovitch
Description: Centralized configuration management for NetProbe.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
"""
import yaml
import os
from pydantic import BaseModel
from typing import Optional

class ServerConfig(BaseModel):
    host: str = "127.0.0.1"
    port: int = 8000
    database_url: str = "sqlite:///./netprobe.db"
    scan_frequency: int = 86400

class AgentConfig(BaseModel):
    server_url: str = "http://127.0.0.1:8000"
    workers: int = 4
    discover: bool = True
    scan: bool = True
    checkin_interval: int = 60

class LoggingConfig(BaseModel):
    level: str = "INFO"
    file: Optional[str] = None

class Config(BaseModel):
    server: ServerConfig
    agent: AgentConfig
    logging: LoggingConfig

def load_config(path: str = "config.yaml") -> Config:
    """
    Loads configuration from a YAML file.
    """
    if os.path.exists(path):
        with open(path, 'r') as f:
            config_data = yaml.safe_load(f)
        return Config(**config_data)
    return Config(server=ServerConfig(), agent=AgentConfig(), logging=LoggingConfig())

# Load environment variables for secrets
from dotenv import load_dotenv
load_dotenv(dotenv_path="conf/.env")

NETPROBE_API_KEY = os.getenv("NETPROBE_API_KEY")
DATABASE_PASSWORD = os.getenv("DATABASE_PASSWORD")

config = load_config("conf/config.yaml")

# Override database URL with password if available
if DATABASE_PASSWORD:
    config.server.database_url = config.server.database_url.replace(
        "<password>", DATABASE_PASSWORD
    )
