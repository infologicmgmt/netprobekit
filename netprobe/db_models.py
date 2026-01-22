"""
Filename: netprobe/db_models.py
Author: Michael Moscovitch
Assistant: Jules
Date: 2026/01/10
Copyright (c) 2026 Michael Moscovitch
Description: Database models for netprobe

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
from sqlalchemy import (
    Column,
    Integer,
    String,
    DateTime,
    ForeignKey,
    Enum,
    BigInteger,
    Boolean,
    UUID,
)
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
import datetime

Base = declarative_base()


class Organization(Base):
    __tablename__ = "organizations"
    id = Column(Integer, primary_key=True)
    name = Column(String(254), nullable=False, unique=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(
        DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow
    )

class Site(Base):
    __tablename__ = "sites"
    id = Column(Integer, primary_key=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    name = Column(String(254), nullable=False)
    physical_address = Column(String(254))
    timezone = Column(String(254))
    organization = relationship("Organization")

class Node(Base):
    __tablename__ = "nodes"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    hostname = Column(String(254), nullable=False)
    management_ip = Column(String(254), nullable=False)
    vendor = Column(String(254))
    model = Column(String(254))
    os_version = Column(String(254))
    snmp_version = Column(Enum("v1", "v2c", "v3", name="snmp_version_enum"), nullable=False)
    snmp_community = Column(String(254))
    last_seen = Column(DateTime, default=datetime.datetime.utcnow)
    discovery_source = Column(Integer)
    interfaces = relationship("Interface", back_populates="node")
    organization = relationship("Organization")

class Interface(Base):
    __tablename__ = "interfaces"
    id = Column(Integer, primary_key=True)
    node_id = Column(UUID(as_uuid=True), ForeignKey("nodes.id"), nullable=False)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    if_index = Column(Integer)
    name = Column(String(254), nullable=False)
    mac_address = Column(String(254))
    status = Column(Enum("Up", "Down", "Testing", name="interface_status_enum"))
    description = Column(String(254))
    vlan_mode = Column(Enum("Access", "Trunk", "General", name="vlan_mode_enum"))
    native_vlan = Column(Integer)
    allowed_vlans = Column(String(254))
    speed_bandwidth = Column(BigInteger)
    mtu = Column(Integer)
    node = relationship("Node", back_populates="interfaces")
    organization = relationship("Organization")

class Vlan(Base):
    __tablename__ = "vlans"
    id = Column(Integer, primary_key=True)
    node_id = Column(UUID(as_uuid=True), ForeignKey("nodes.id"), nullable=False)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    vlan_number = Column(Integer, nullable=False)
    vlan_name = Column(String(254))
    is_active = Column(Boolean, default=True)
    node = relationship("Node")
    organization = relationship("Organization")

class Neighbor(Base):
    __tablename__ = "neighbors"
    id = Column(Integer, primary_key=True)
    local_interface_id = Column(Integer, ForeignKey("interfaces.id"), nullable=False)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    remote_node_hostname = Column(String(254))
    remote_interface_name = Column(String(254))
    remote_mgmt_ip = Column(String(254))
    local_interface = relationship("Interface")
    organization = relationship("Organization")

class RoutingTable(Base):
    __tablename__ = "routing_tables"
    id = Column(Integer, primary_key=True)
    node_id = Column(UUID(as_uuid=True), ForeignKey("nodes.id"), nullable=False)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    destination_cidr = Column(String(254), nullable=False)
    next_hop = Column(String(254))
    interface_id = Column(Integer, ForeignKey("interfaces.id"))
    node = relationship("Node")
    interface = relationship("Interface")
    organization = relationship("Organization")

class ArpTable(Base):
    __tablename__ = "arp_tables"
    id = Column(Integer, primary_key=True)
    node_id = Column(UUID(as_uuid=True), ForeignKey("nodes.id"), nullable=False)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    ip_address = Column(String(254), nullable=False)
    mac_address = Column(String(254))
    interface_name = Column(String(254))
    last_updated = Column(DateTime, default=datetime.datetime.utcnow)
    node = relationship("Node")
    organization = relationship("Organization")

class MacAddressTable(Base):
    __tablename__ = "mac_address_tables"
    id = Column(Integer, primary_key=True)
    interface_id = Column(Integer, ForeignKey("interfaces.id"), nullable=False)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    mac_address = Column(String(254), nullable=False)
    vlan_id = Column(Integer)
    type = Column(Enum("Static", "Dynamic", name="mac_address_type_enum"))
    interface = relationship("Interface")
    organization = relationship("Organization")

class ScanProfile(Base):
    __tablename__ = "scan_profiles"
    id = Column(Integer, primary_key=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    name = Column(String(254), nullable=False)
    nmap_arguments = Column(String(254))
    frequency = Column(String(254))
    organization = relationship("Organization")

class SnmpConfig(Base):
    __tablename__ = "snmp_configs"
    id = Column(Integer, primary_key=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    version = Column(Enum("v1", "v2c", "v3", name="snmp_version_enum"), nullable=False)
    community_string = Column(String(254))
    v3_username = Column(String(254))
    v3_auth_key = Column(String(254))
    v3_priv_key = Column(String(254))
    organization = relationship("Organization")

class ApiKey(Base):
    __tablename__ = "api_keys"
    id = Column(Integer, primary_key=True)
    agent_uuid = Column(UUID(as_uuid=True), default=uuid.uuid4, nullable=False)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    api_key_hash = Column(String(254), nullable=False)
    last_checkin = Column(DateTime, default=datetime.datetime.utcnow)
    is_active = Column(Boolean, default=True)
    organization = relationship("Organization")

class ScanTarget(Base):
    __tablename__ = "scan_targets"
    target_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    site_id = Column(Integer, ForeignKey("sites.id"), nullable=False)
    network_cidr = Column(String(254), nullable=False)
    snmp_profile_id = Column(Integer, ForeignKey("snmp_configs.id"), nullable=False)
    scan_profile_id = Column(Integer, ForeignKey("scan_profiles.id"), nullable=False)
    is_active = Column(Boolean, default=True)
    organization = relationship("Organization")
    site = relationship("Site")
    snmp_profile = relationship("SnmpConfig")
    scan_profile = relationship("ScanProfile")
