"""
Filename: netprobe/endpoints.py
Author: Michael Moscovitch
Assistant: Jules
Date: 2026/01/10
Copyright (c) 2026 Michael Moscovitch
Description: API endpoints for netprobe server

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
import datetime
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from netprobe import schemas, db_models
from netprobe.database import SessionLocal

router = APIRouter()

# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@router.post("/orgs/", response_model=schemas.Organization)
def create_organization(org: schemas.OrganizationCreate, db: Session = Depends(get_db)):
    db_org = db_models.Organization(name=org.name)
    db.add(db_org)
    db.commit()
    db.refresh(db_org)
    return db_org

@router.get("/orgs/", response_model=List[schemas.Organization])
def read_organizations(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    orgs = db.query(db_models.Organization).offset(skip).limit(limit).all()
    return orgs

@router.post("/sites/", response_model=schemas.Site)
def create_site(site: schemas.SiteCreate, db: Session = Depends(get_db)):
    db_site = db_models.Site(**site.dict())
    db.add(db_site)
    db.commit()
    db.refresh(db_site)
    return db_site

@router.get("/sites/", response_model=List[schemas.Site])
def read_sites(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    sites = db.query(db_models.Site).offset(skip).limit(limit).all()
    return sites

@router.get("/sites/{site_id}", response_model=schemas.Site)
def read_site(site_id: int, db: Session = Depends(get_db)):
    db_site = db.query(db_models.Site).filter(db_models.Site.id == site_id).first()
    if db_site is None:
        raise HTTPException(status_code=404, detail="Site not found")
    return db_site

@router.put("/sites/{site_id}", response_model=schemas.Site)
def update_site(site_id: int, site: schemas.SiteCreate, db: Session = Depends(get_db)):
    db_site = db.query(db_models.Site).filter(db_models.Site.id == site_id).first()
    if db_site is None:
        raise HTTPException(status_code=404, detail="Site not found")
    for var, value in vars(site).items():
        setattr(db_site, var, value) if value else None
    db.add(db_site)
    db.commit()
    db.refresh(db_site)
    return db_site

@router.delete("/sites/{site_id}", response_model=schemas.Site)
def delete_site(site_id: int, db: Session = Depends(get_db)):
    db_site = db.query(db_models.Site).filter(db_models.Site.id == site_id).first()
    if db_site is None:
        raise HTTPException(status_code=404, detail="Site not found")
    db.delete(db_site)
    db.commit()
    return db_site

@router.post("/nodes/", response_model=schemas.Node)
def create_or_update_node(node: schemas.NodeCreate, db: Session = Depends(get_db)):
    db_node = db.query(db_models.Node).filter(db_models.Node.management_ip == node.management_ip).first()
    if db_node:
        update_data = node.dict(exclude_unset=True)
        for key, value in update_data.items():
            setattr(db_node, key, value)
    else:
        db_node = db_models.Node(**node.dict())
        db.add(db_node)

    db.commit()
    db.refresh(db_node)
    return db_node

@router.get("/nodes/", response_model=List[schemas.Node])
def read_nodes(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    nodes = db.query(db_models.Node).offset(skip).limit(limit).all()
    return nodes

@router.get("/nodes/{node_id}", response_model=schemas.Node)
def read_node(node_id: uuid.UUID, db: Session = Depends(get_db)):
    db_node = db.query(db_models.Node).filter(db_models.Node.id == node_id).first()
    if db_node is None:
        raise HTTPException(status_code=404, detail="Node not found")
    return db_node

@router.put("/nodes/{node_id}", response_model=schemas.Node)
def update_node(node_id: uuid.UUID, node: schemas.NodeCreate, db: Session = Depends(get_db)):
    db_node = db.query(db_models.Node).filter(db_models.Node.id == node_id).first()
    if db_node is None:
        raise HTTPException(status_code=404, detail="Node not found")
    for var, value in vars(node).items():
        setattr(db_node, var, value) if value else None
    db.add(db_node)
    db.commit()
    db.refresh(db_node)
    return db_node

@router.delete("/nodes/{node_id}", response_model=schemas.Node)
def delete_node(node_id: uuid.UUID, db: Session = Depends(get_db)):
    db_node = db.query(db_models.Node).filter(db_models.Node.id == node_id).first()
    if db_node is None:
        raise HTTPException(status_code=404, detail="Node not found")
    db.delete(db_node)
    db.commit()
    return db_node

@router.post("/interfaces/", response_model=List[schemas.Interface])
def create_interfaces(interfaces: List[schemas.InterfaceCreate], db: Session = Depends(get_db)):
    db_interfaces = [db_models.Interface(**interface.dict()) for interface in interfaces]
    db.add_all(db_interfaces)
    db.commit()
    return db_interfaces

@router.get("/interfaces/", response_model=List[schemas.Interface])
def read_interfaces(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    interfaces = db.query(db_models.Interface).offset(skip).limit(limit).all()
    return interfaces

@router.post("/routing-tables/", response_model=List[schemas.RoutingTable])
def create_routing_tables(routing_tables: List[schemas.RoutingTableCreate], db: Session = Depends(get_db)):
    db_routing_tables = [db_models.RoutingTable(**routing_table.dict()) for routing_table in routing_tables]
    db.add_all(db_routing_tables)
    db.commit()
    return db_routing_tables

@router.get("/routing-tables/", response_model=List[schemas.RoutingTable])
def read_routing_tables(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    routing_tables = db.query(db_models.RoutingTable).offset(skip).limit(limit).all()
    return routing_tables

@router.post("/arp-tables/", response_model=List[schemas.ArpTable])
def create_arp_tables(arp_tables: List[schemas.ArpTableCreate], db: Session = Depends(get_db)):
    db_arp_tables = [db_models.ArpTable(**arp_table.dict()) for arp_table in arp_tables]
    db.add_all(db_arp_tables)
    db.commit()
    return db_arp_tables

@router.get("/arp-tables/", response_model=List[schemas.ArpTable])
def read_arp_tables(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    arp_tables = db.query(db_models.ArpTable).offset(skip).limit(limit).all()
    return arp_tables

@router.post("/mac-address-tables/", response_model=List[schemas.MacAddressTable])
def create_mac_address_tables(mac_address_tables: List[schemas.MacAddressTableCreate], db: Session = Depends(get_db)):
    db_mac_address_tables = [db_models.MacAddressTable(**mac_address_table.dict()) for mac_address_table in mac_address_tables]
    db.add_all(db_mac_address_tables)
    db.commit()
    return db_mac_address_tables

@router.get("/mac-address-tables/", response_model=List[schemas.MacAddressTable])
def read_mac_address_tables(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    mac_address_tables = db.query(db_models.MacAddressTable).offset(skip).limit(limit).all()
    return mac_address_tables

@router.post("/checkin/")
def agent_checkin(agent_info: schemas.AgentCheckin, db: Session = Depends(get_db)):
    """
    Handles agent check-ins, updating their last_seen time.
    """
    db_api_key = db.query(db_models.ApiKey).filter(db_models.ApiKey.agent_uuid == agent_info.agent_uuid).first()
    if not db_api_key:
        # In a real-world scenario, you might want to register the new agent
        # For now, we'll assume agents must be pre-registered.
        raise HTTPException(status_code=404, detail="Agent not registered")

    db_api_key.last_checkin = datetime.datetime.utcnow()
    db.commit()
    return {"message": "Check-in successful"}

@router.get("/tasks/", response_model=schemas.TaskList)
def get_tasks(db: Session = Depends(get_db)):
    """
    Provides a list of scan tasks for an agent.
    """
    scan_targets = db.query(db_models.ScanTarget).filter(db_models.ScanTarget.is_active == True).all()
    tasks = []
    for target in scan_targets:
        tasks.append({
            "type": "nmap_snmp_scan",
            "target_id": target.target_id,
            "network_cidr": str(target.network_cidr),
            "snmp_config": schemas.SnmpConfig.from_orm(target.snmp_profile),
            "scan_profile": schemas.ScanProfile.from_orm(target.scan_profile)
        })
    return {"tasks": tasks}

@router.post("/batch-submit/")
def batch_submit(data: schemas.BatchSubmit, db: Session = Depends(get_db)):
    """
    Allows agents to submit a batch of discovered data.
    """
    if data.nodes:
        for node in data.nodes:
            create_or_update_node(node, db)
    if data.interfaces:
        create_interfaces(data.interfaces, db)
    if data.routing_tables:
        create_routing_tables(data.routing_tables, db)
    if data.arp_tables:
        create_arp_tables(data.arp_tables, db)
    if data.mac_address_tables:
        create_mac_address_tables(data.mac_address_tables, db)
    return {"message": "Batch submission successful"}


@router.get("/reports/switchport/", response_model=List[schemas.SwitchPortReport])
def get_switchport_report(db: Session = Depends(get_db)):
    """
    Generates the switch port mapping report by joining across multiple tables.
    """
    results = (
        db.query(
            db_models.Node.hostname,
            db_models.Interface.name,
            db_models.MacAddressTable.mac_address,
            db_models.MacAddressTable.vlan_id
        )
        .join(db_models.Interface, db_models.Node.id == db_models.Interface.node_id)
        .join(db_models.MacAddressTable, db_models.Interface.id == db_models.MacAddressTable.interface_id)
        .filter(db_models.MacAddressTable.type == 'Dynamic')
        .all()
    )

    report_data = [
        {
            "switch": hostname,
            "port": if_name,
            "mac_address": mac,
            "vlan": vlan
        }
        for hostname, if_name, mac, vlan in results
    ]
    return report_data

@router.get("/reports/topology/", response_model=schemas.Topology)
def get_topology_report(db: Session = Depends(get_db)):
    """
    Generates the network topology report.
    """
    nodes = db.query(db_models.Node).all()
    neighbors = db.query(db_models.Neighbor).all()

    topology_nodes = [{"id": str(node.id), "label": node.hostname} for node in nodes]
    topology_edges = []
    for neighbor in neighbors:
        local_node = db.query(db_models.Node).join(db_models.Interface).filter(db_models.Interface.id == neighbor.local_interface_id).first()
        remote_node = db.query(db_models.Node).filter(db_models.Node.hostname == neighbor.remote_node_hostname).first()
        if local_node and remote_node:
            topology_edges.append({"source": str(local_node.id), "target": str(remote_node.id)})

    return {"nodes": topology_nodes, "edges": topology_edges}
