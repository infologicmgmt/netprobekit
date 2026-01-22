"""
Filename: netprobe/agent.py
Author: Michael Moscovitch
Assistant: Jules
Date: 2026/01/10
Description: Agent component of netprobe
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
import logging
import requests
import time
import uuid
from pysnmp.entity.engine import SnmpEngine
from pysnmp_sync_adapter import get_cmd_sync, next_cmd_sync
from pysnmp.hlapi.v3arch.asyncio.context import ContextData
from pysnmp.hlapi.v1arch.asyncio import (
    CommunityData,
    UdpTransportTarget,
    ObjectType,
    ObjectIdentity,
)
import nmap
from netprobe.config import config, NETPROBE_API_KEY
from netprobe import constants

# Set up logging
logging.basicConfig(level=config.logging.level, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def snmp_get(ip_address, community, oid):
    """
    Performs a single SNMP GET operation.
    """
    errorIndication, errorStatus, errorIndex, varBinds = get_cmd_sync(
        SnmpEngine(),
        CommunityData(community),
        UdpTransportTarget.create((ip_address, 161)),
        ContextData(),
        ObjectType(ObjectIdentity(oid))
    )
    if errorIndication:
        logger.error(f"SNMP GET for {oid} failed: {errorIndication}")
        return None
    elif errorStatus:
        logger.error(f'SNMP GET for {oid} failed: {errorStatus.prettyPrint()} at {errorIndex and varBinds[int(errorIndex) - 1][0] or "?"}')
        return None
    return str(varBinds[0][1]) if varBinds else None

def snmp_walk(ip_address, community, oid):
    """
    Performs an SNMP WALK operation to retrieve a table of data.
    """
    results = {}
    for (errorIndication, errorStatus, errorIndex, varBinds) in next_cmd_sync(
            SnmpEngine(),
            CommunityData(community),
            UdpTransportTarget.create((ip_address, 161)),
            ContextData(),
            ObjectType(ObjectIdentity(oid)),
            lexicographicMode=False):

        if errorIndication:
            logger.error(f"SNMP WALK for {oid} failed: {errorIndication}")
            return None
        elif errorStatus:
            logger.error(f'SNMP WALK for {oid} failed: {errorStatus.prettyPrint()} at {errorIndex and varBinds[int(errorIndex) - 1][0] or "?"}')
            return None
        else:
            for varBind in varBinds:
                full_oid = str(varBind[0])
                index = full_oid[len(oid)+1:]
                results[index] = str(varBind[1])
    return results

def scan_nmap(network, options='-sP'):
    """
    Performs a basic Nmap scan on a network.
    """
    nm = nmap.PortScanner()
    nm.scan(hosts=network, arguments=options)
    hosts_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]
    return hosts_list

def _submit_data(payload, headers, endpoint="submit_data"):
    """
    Submits a data payload to a specified server endpoint.
    """
    try:
        response = requests.post(
            f"{config.agent.server_url}/{endpoint}/",
            headers=headers,
            json=payload
        )
        response.raise_for_status()
        logger.info(f"Successfully submitted data to {endpoint}")
        return response.json()
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to submit data to {endpoint}: {e}")
        return None

def _collect_interfaces(node_ip, community, node_id, org_id):
    """
    Collects interface data from a device.
    """
    if_names = snmp_walk(node_ip, community, constants.IF_NAME_OID)
    if not if_names:
        logger.warning(f"Could not retrieve interface names for {node_ip}")
        return []

    interfaces = []
    for index, name in if_names.items():
        interfaces.append({
            "node_id": node_id,
            "org_id": org_id,
            "if_index": int(index),
            "name": name,
        })
    return interfaces

def _get_interface_id(interfaces, if_index):
    """
    Looks up the database ID of an interface from its ifIndex.
    """
    for interface in interfaces:
        if interface["if_index"] == if_index:
            return interface["id"]
    return None

def _collect_routing_table(node_ip, community, node_id, org_id, interfaces):
    """
    Collects routing table data from a device.
    """
    route_dests = snmp_walk(node_ip, community, constants.IP_ROUTE_DEST_OID)
    route_next_hops = snmp_walk(node_ip, community, constants.IP_ROUTE_NEXT_HOP_OID)
    route_if_indexes = snmp_walk(node_ip, community, constants.IP_ROUTE_IF_INDEX_OID)

    if not route_dests:
        logger.warning(f"Could not retrieve routing table for {node_ip}")
        return []

    routing_table = []
    for index, dest in route_dests.items():
        if_index = route_if_indexes.get(index)
        interface_id = _get_interface_id(interfaces, if_index) if if_index else None
        routing_table.append({
            "node_id": node_id,
            "org_id": org_id,
            "destination_cidr": dest,
            "next_hop": route_next_hops.get(index),
            "interface_id": interface_id,
        })
    return routing_table

def _collect_arp_table(node_ip, community, node_id, org_id):
    """
    Collects ARP table data from a device.
    """
    arp_ips = snmp_walk(node_ip, community, constants.ARP_IP_ADDRESS_OID)
    arp_macs = snmp_walk(node_ip, community, constants.ARP_MAC_ADDRESS_OID)

    if not arp_ips:
        logger.warning(f"Could not retrieve ARP table for {node_ip}")
        return []

    arp_table = []
    for index, ip in arp_ips.items():
        arp_table.append({
            "node_id": node_id,
            "org_id": org_id,
            "ip_address": ip,
            "mac_address": arp_macs.get(index),
        })
    return arp_table

def _collect_mac_address_table(node_ip, community, node_id, org_id, interfaces):
    """
    Collects MAC address table data from a device.
    """
    mac_addresses = snmp_walk(node_ip, community, constants.MAC_ADDRESS_TABLE_MAC_OID)
    mac_ports = snmp_walk(node_ip, community, constants.MAC_ADDRESS_TABLE_PORT_OID)
    mac_statuses = snmp_walk(node_ip, community, constants.MAC_ADDRESS_TABLE_STATUS_OID)

    if not mac_addresses:
        logger.warning(f"Could not retrieve MAC address table for {node_ip}")
        return []

    mac_address_table = []
    for index, mac in mac_addresses.items():
        if_index = mac_ports.get(index)
        interface_id = _get_interface_id(interfaces, if_index) if if_index else None
        mac_address_table.append({
            "node_id": node_id,
            "org_id": org_id,
            "mac_address": mac,
            "interface_id": interface_id,
            "type": mac_statuses.get(index),
        })
    return mac_address_table


def execute_task(task, headers):
    """
    Executes a scan task, gathers data, and submits it to the server.
    """
    logger.info(f"Executing task {task['target_id']} for network {task['network_cidr']}")
    discovered_hosts = scan_nmap(task['network_cidr'], options=task['scan_profile']['nmap_arguments'])

    batch_data = {
        "nodes": [],
        "interfaces": [],
        "routing_tables": [],
        "arp_tables": [],
        "mac_address_tables": [],
    }

    for host_ip, status in discovered_hosts:
        if status != 'up':
            continue

        logger.info(f"Probing host: {host_ip}")
        snmp_community = task['snmp_config']['community_string']
        system_description = snmp_get(host_ip, snmp_community, constants.SYS_DESCR_OID)

        if not system_description:
            logger.warning(f"No SNMP response from {host_ip}, skipping...")
            continue

        vendor = "Unknown"
        if "cisco" in system_description.lower(): vendor = "Cisco"
        elif "fortinet" in system_description.lower(): vendor = "Fortinet"

        node_data = {
            "hostname": snmp_get(host_ip, snmp_community, constants.SYS_NAME_OID) or f"unknown-{host_ip}",
            "management_ip": host_ip, "vendor": vendor, "os_version": system_description,
            "snmp_version": task['snmp_config']['version'], "snmp_community": snmp_community,
            "discovery_source": 1, "org_id": task['snmp_config']['org_id']
        }

        submission_response = _submit_data(node_data, headers, endpoint="nodes")
        if submission_response and "id" in submission_response:
            node_id = submission_response["id"]
            org_id = task['snmp_config']['org_id']

            interfaces = _collect_interfaces(host_ip, snmp_community, node_id, org_id)
            batch_data["interfaces"].extend(interfaces)
            batch_data["routing_tables"].extend(_collect_routing_table(host_ip, snmp_community, node_id, org_id, interfaces))
            batch_data["arp_tables"].extend(_collect_arp_table(host_ip, snmp_community, node_id, org_id))
            batch_data["mac_address_tables"].extend(_collect_mac_address_table(host_ip, snmp_community, node_id, org_id, interfaces))

    if any(batch_data.values()):
        _submit_data(batch_data, headers, endpoint="batch-submit")


import asyncio
from concurrent.futures import ThreadPoolExecutor

async def run_in_executor(loop, executor, func, *args, **kwargs):
    """Run a synchronous function in an executor."""
    return await loop.run_in_executor(executor, lambda: func(*args, **kwargs))

async def main():
    """Main function for the agent."""
    logger.info("Starting Netprobe Agent...")

    if not NETPROBE_API_KEY:
        logger.error("API key not found. Set NETPROBE_API_KEY environment variable.")
        return

    agent_uuid = str(uuid.uuid4())
    headers = {"X-API-Key": NETPROBE_API_KEY}

    loop = asyncio.get_running_loop()
    with ThreadPoolExecutor(max_workers=config.agent.workers) as executor:
        while True:
            try:
                response = await run_in_executor(loop, executor, requests.post, url=f"{config.agent.server_url}/checkin/", headers=headers, json={"agent_uuid": agent_uuid})
                response.raise_for_status()
                logger.info("Checked in with server.")

                response = await run_in_executor(loop, executor, requests.get, url=f"{config.agent.server_url}/tasks/", headers=headers)
                response.raise_for_status()
                tasks = response.json().get("tasks", [])
                logger.info(f"Received {len(tasks)} tasks.")

                await asyncio.gather(
                    *[run_in_executor(loop, executor, execute_task, task, headers) for task in tasks]
                )

            except Exception as e:
                logger.error(f"An error occurred: {e}")

            await asyncio.sleep(config.agent.checkin_interval)

if __name__ == "__main__":
    asyncio.run(main())
