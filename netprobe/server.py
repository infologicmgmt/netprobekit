"""
Filename: netprobe/server.py
Author: Michael Moscovitch
Assistant: Jules
Date: 2026/01/10
Description: FastAPI server for netprobe
Copyright (c) 2026 Michael Moscovitch

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
from fastapi import FastAPI, Depends
from netprobe import endpoints
from netprobe.security import get_api_key

app = FastAPI(dependencies=[Depends(get_api_key)])

app.include_router(endpoints.router)

@app.get("/")
def read_root():
    return {"Hello": "World"}
