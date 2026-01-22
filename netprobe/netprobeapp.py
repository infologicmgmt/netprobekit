"""
Filename: netprobe/netprobeapp.py
Author: Michael Moscovitch
Assistant: Jules
Date: 2026/01/10
Copyright (c) 2026 Michael Moscovitch
Description: Core application logic for netprobe

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
import csv
import os
import requests
import yaml
import graphviz
from vsdx import VisioFile
import xlsxwriter

from netprobe.config import load_config
from netprobe.database import engine, Base

class NetProbeApp:
    __version__ = "0.1.0"

    def __init__(self):
        self.config = load_config()
        self.api_key = os.getenv("NETPROBE_API_KEY")
        if not self.api_key:
            raise ValueError("API key not found. Set NETPROBE_API_KEY environment variable.")
        self.server_url = self.config.agent.server_url
        self.headers = {"X-API-Key": self.api_key}

    def show_config(self):
        """Return the current configuration as a JSON string."""
        return self.config.model_dump_json(indent=2)

    def add_node(self, target, snmp_version, snmp_community, org_id):
        """Add a new node."""
        response = requests.post(f"{self.server_url}/nodes/", headers=self.headers, json={
            "hostname": f"manual-{target}",
            "management_ip": target,
            "snmp_version": snmp_version,
            "snmp_community": snmp_community,
            "org_id": org_id,
        })
        if response.status_code == 200:
            return f"Node {target} added successfully."
        else:
            return f"Error adding node: {response.text}"

    def delete_node(self, target):
        """Delete a node."""
        response = requests.delete(f"{self.server_url}/nodes/{target}", headers=self.headers)
        if response.status_code == 200:
            return f"Node {target} deleted successfully."
        else:
            return f"Error deleting node: {response.text}"

    def scan(self, target, site_id, snmp_profile_id, scan_profile_id, org_id):
        """Initiate a scan on a network."""
        response = requests.post(f"{self.server_url}/scan-targets/", headers=self.headers, json={
            "network_cidr": target,
            "site_id": site_id,
            "snmp_profile_id": snmp_profile_id,
            "scan_profile_id": scan_profile_id,
            "org_id": org_id,
        })
        if response.status_code == 200:
            return f"Scan for {target} initiated successfully."
        else:
            return f"Error initiating scan: {response.text}"

    def manage_config(self, set_var):
        """Manage configuration."""
        config_path = "conf/config.yaml"
        if set_var:
            try:
                with open(config_path, 'r') as f:
                    config_data = yaml.safe_load(f) or {}

                key, value = set_var.split('=', 1)
                keys = key.split('.')
                d = config_data
                for k in keys[:-1]:
                    d = d.setdefault(k, {})
                d[keys[-1]] = value

                with open(config_path, 'w') as f:
                    yaml.dump(config_data, f)

                return f"Set {key} = {value}"

            except Exception as e:
                return f"Error updating config file: {e}"
        else:
            return self.show_config()

    def report_topology(self, format):
        """Generate a network topology map."""
        try:
            response = requests.get(f"{self.server_url}/reports/topology/", headers=self.headers)
            response.raise_for_status()
            data = response.json()

            if format == 'visio':
                with VisioFile() as vis:
                    page = vis.add_page("Topology")
                    for node in data['nodes']:
                        page.add_shape(node['label'])
                    vis.save_vsdx("topology.vsdx")
                return "Topology map generated as topology.vsdx"

            else:
                dot = graphviz.Digraph(comment='Network Topology')
                for node in data['nodes']:
                    dot.node(node['id'], node['label'])
                for edge in data['edges']:
                    dot.edge(edge['source'], edge['target'])

                output_filename = f"topology"
                dot.render(output_filename, format=format, view=False, cleanup=True)
                return f"Topology map generated as {output_filename}.{format}"

        except requests.exceptions.RequestException as e:
            return f"Could not connect to server: {e}"
        except Exception as e:
            return f"Error generating topology map: {e}"

    def report_switchport(self, format):
        """Generate a switch port mapping report."""
        try:
            response = requests.get(f"{self.server_url}/reports/switchport/", headers=self.headers)
            response.raise_for_status()
            data = response.json()

            if not data:
                return "No switch port data available."

            if format == 'csv':
                fieldnames = ["switch", "port", "mac_address", "vlan"]
                with open('switchport_report.csv', 'w', newline='') as csvfile:
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                    writer.writeheader()
                    writer.writerows(data)
                return "Switch port report generated as switchport_report.csv"

            elif format == 'xlsx':
                workbook = xlsxwriter.Workbook('switchport_report.xlsx')
                worksheet = workbook.add_worksheet()

                headers = ["Switch", "Port", "MAC Address", "VLAN"]
                for col, header in enumerate(headers):
                    worksheet.write(0, col, header)

                for row, item in enumerate(data, start=1):
                    worksheet.write(row, 0, item['switch'])
                    worksheet.write(row, 1, item['port'])
                    worksheet.write(row, 2, item['mac_address'])
                    worksheet.write(row, 3, item['vlan'])

                workbook.close()
                return "Switch port report generated as switchport_report.xlsx"

        except requests.exceptions.RequestException as e:
            return f"Could not connect to server: {e}"

    def init_db(self):
        """Initialize the database."""
        try:
            Base.metadata.create_all(bind=engine)
            return "Database initialized successfully."
        except Exception as e:
            return f"Error initializing database: {e}"

    def get_version(self):
        """Return the application version."""
        return self.__version__
