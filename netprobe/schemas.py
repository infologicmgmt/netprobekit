"""
Filename: netprobe/schemas.py
Author: Michael Moscovitch
Assistant: Jules
Date: 2026/01/10
Copyright (c) 2026 Michael Moscovitch
Description: Pydantic schemas for netprobe

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
import uuid
from pydantic import BaseModel
from datetime import datetime
from typing import List, Any

class OrganizationBase(BaseModel):
    name: str

class OrganizationCreate(OrganizationBase):
    pass

class Organization(OrganizationBase):
    id: int
    created_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True

class NeighborBase(BaseModel):
    remote_node_hostname: str | None = None
    remote_interface_name: str | None = None
    remote_mgmt_ip: str | None = None

class NeighborCreate(NeighborBase):
    local_interface_id: int
    org_id: int

class Neighbor(NeighborBase):
    id: int
    local_interface_id: int
    org_id: int

    class Config:
        orm_mode = True

class RoutingTableBase(BaseModel):
    destination_cidr: str
    next_hop: str | None = None

class RoutingTableCreate(RoutingTableBase):
    node_id: uuid.UUID
    org_id: int
    interface_id: int | None = None

class RoutingTable(RoutingTableBase):
    id: int
    node_id: uuid.UUID
    org_id: int
    interface_id: int | None = None

    class Config:
        orm_mode = True

class ArpTableBase(BaseModel):
    ip_address: str
    mac_address: str | None = None
    interface_name: str | None = None

class ArpTableCreate(ArpTableBase):
    node_id: uuid.UUID
    org_id: int

class ArpTable(ArpTableBase):
    id: int
    node_id: uuid.UUID
    org_id: int
    last_updated: datetime

    class Config:
        orm_mode = True

class MacAddressTableBase(BaseModel):
    mac_address: str
    vlan_id: int | None = None
    type: str | None = None

class MacAddressTableCreate(MacAddressTableBase):
    interface_id: int
    org_id: int

class MacAddressTable(MacAddressTableBase):
    id: int
    interface_id: int
    org_id: int

    class Config:
        orm_mode = True

class ScanProfileBase(BaseModel):
    name: str
    nmap_arguments: str | None = None
    frequency: str | None = None

class ScanProfileCreate(ScanProfileBase):
    org_id: int

class ScanProfile(ScanProfileBase):
    id: int
    org_id: int

    class Config:
        orm_mode = True

class SnmpConfigBase(BaseModel):
    version: str
    community_string: str | None = None
    v3_username: str | None = None
    v3_auth_key: str | None = None
    v3_priv_key: str | None = None

class SnmpConfigCreate(SnmpConfigBase):
    org_id: int

class SnmpConfig(SnmpConfigBase):
    id: int
    org_id: int

    class Config:
        orm_mode = True

class ApiKeyBase(BaseModel):
    agent_uuid: uuid.UUID
    api_key_hash: str
    is_active: bool = True

class ApiKeyCreate(ApiKeyBase):
    org_id: int

class ApiKey(ApiKeyBase):
    id: int
    org_id: int
    last_checkin: datetime

    class Config:
        orm_mode = True

class SiteBase(BaseModel):
    name: str
    physical_address: str | None = None
    timezone: str | None = None

class SiteCreate(SiteBase):
    org_id: int

class Site(SiteBase):
    id: int
    org_id: int

    class Config:
        orm_mode = True

class NodeBase(BaseModel):
    hostname: str
    management_ip: str
    vendor: str | None = None
    model: str | None = None
    os_version: str | None = None
    snmp_version: str
    snmp_community: str | None = None
    discovery_source: int | None = None

class NodeCreate(NodeBase):
    org_id: int

class Node(NodeBase):
    id: uuid.UUID
    org_id: int
    last_seen: datetime

    class Config:
        orm_mode = True

class InterfaceBase(BaseModel):
    if_index: int | None = None
    name: str
    mac_address: str | None = None
    status: str | None = None
    description: str | None = None
    vlan_mode: str | None = None
    native_vlan: int | None = None
    allowed_vlans: str | None = None
    speed_bandwidth: int | None = None
    mtu: int | None = None

class InterfaceCreate(InterfaceBase):
    node_id: uuid.UUID
    org_id: int

class Interface(InterfaceBase):
    id: int
    node_id: uuid.UUID
    org_id: int

    class Config:
        orm_mode = True

class VlanBase(BaseModel):
    vlan_number: int
    vlan_name: str | None = None
    is_active: bool = True

class VlanCreate(VlanBase):
    node_id: uuid.UUID
    org_id: int

class Vlan(VlanBase):
    id: int
    node_id: uuid.UUID
    org_id: int

    class Config:
        orm_mode = True

class AgentCheckin(BaseModel):
    agent_uuid: uuid.UUID

class Task(BaseModel):
    type: str
    target_id: uuid.UUID
    network_cidr: str
    snmp_config: SnmpConfig
    scan_profile: ScanProfile

class TaskList(BaseModel):
    tasks: List[Task]

class SwitchPortReport(BaseModel):
    switch: str
    port: str
    mac_address: str
    vlan: int

class BatchSubmit(BaseModel):
    nodes: List[NodeCreate] = []
    interfaces: List[InterfaceCreate] = []
    routing_tables: List[RoutingTableCreate] = []
    arp_tables: List[ArpTableCreate] = []
    mac_address_tables: List[MacAddressTableCreate] = []

class TopologyNode(BaseModel):
    id: str
    label: str

class TopologyEdge(BaseModel):
    source: str
    target: str

class Topology(BaseModel):
    nodes: List[TopologyNode]
    edges: List[TopologyEdge]
