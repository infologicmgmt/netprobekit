"""
Filename: netprobe/security.py
Author: Michael Moscovitch
Assistant: Jules
Date: 2026/01/10
Copyright (c) 2026 Michael Moscovitch
Description: API Key authentication for NetProbe server.

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
from fastapi import Security, HTTPException, status, Depends
from fastapi.security.api_key import APIKeyHeader
from sqlalchemy.orm import Session
from netprobe.database import get_db
from netprobe.db_models import ApiKey
import hashlib

API_KEY_NAME = "X-API-Key"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

async def get_api_key(
    api_key_header: str = Security(api_key_header),
    db: Session = Depends(get_db),
):
    """
    Retrieves and validates the API key from the request header.
    """
    if not api_key_header:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="API key is missing."
        )

    api_key_hash = hashlib.sha256(api_key_header.encode()).hexdigest()
    db_api_key = db.query(ApiKey).filter(ApiKey.api_key_hash == api_key_hash).first()

    if not db_api_key or not db_api_key.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid or inactive API key."
        )

    return db_api_key
