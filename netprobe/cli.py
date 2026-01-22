"""
Filename: netprobe/cli.py
Author: Michael Moscovitch
Assistant: Jules
Date: 2026/01/10
Description: CLI for netprobe
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
import click
from netprobe.netprobeapp import NetProbeApp

@click.group()
@click.pass_context
def cli(ctx):
    """A CLI for interacting with the Netprobe server."""
    try:
        ctx.obj = NetProbeApp()
    except ValueError as e:
        click.echo(e, err=True)
        ctx.exit(1)

@cli.command()
@click.pass_context
def show_config(ctx):
    """Show the current configuration."""
    click.echo(ctx.obj.show_config())

@cli.command()
@click.option('--target', required=True, help='The IP address of the node to add.')
@click.option('--snmp-version', type=click.Choice(['v1', 'v2c', 'v3']), default='v2c', help='SNMP version.')
@click.option('--snmp-community', default='public', help='SNMP community string.')
@click.option('--org-id', required=True, type=int, help='The ID of the organization to associate the node with.')
@click.pass_context
def add(ctx, target, snmp_version, snmp_community, org_id):
    """Add a new node."""
    result = ctx.obj.add_node(target, snmp_version, snmp_community, org_id)
    click.echo(result)

@cli.command()
@click.option('--target', required=True, help='The ID of the node to delete.')
@click.pass_context
def delete(ctx, target):
    """Delete a node."""
    result = ctx.obj.delete_node(target)
    click.echo(result)

@cli.command()
@click.option('--target', required=True, help='The network to scan (e.g., 192.168.1.0/24).')
@click.option('--site-id', required=True, type=int, help='The ID of the site to associate the scan with.')
@click.option('--snmp-profile-id', required=True, type=int, help='The ID of the SNMP profile to use.')
@click.option('--scan-profile-id', required=True, type=int, help='The ID of the scan profile to use.')
@click.option('--org-id', required=True, type=int, help='The ID of the organization to associate the scan with.')
@click.pass_context
def scan(ctx, target, site_id, snmp_profile_id, scan_profile_id, org_id):
    """Initiate a scan on a network."""
    result = ctx.obj.scan(target, site_id, snmp_profile_id, scan_profile_id, org_id)
    click.echo(result)

@cli.command()
@click.option('--set', 'set_var', help='Set a configuration value (e.g., agent.server_url=http://localhost:8000).')
@click.pass_context
def config(ctx, set_var):
    """Manage configuration."""
    result = ctx.obj.manage_config(set_var)
    click.echo(result)

@cli.group()
def report():
    """Generate reports."""
    pass

@report.command()
@click.option('--format', type=click.Choice(['pdf', 'png', 'visio']), default='png', help='Output format.')
@click.pass_context
def topology(ctx, format):
    """Generate a network topology map."""
    result = ctx.obj.report_topology(format)
    click.echo(result)

@report.command()
@click.option('--format', type=click.Choice(['csv', 'xlsx']), default='csv', help='Output format.')
@click.pass_context
def switchport(ctx, format):
    """Generate a switch port mapping report."""
    result = ctx.obj.report_switchport(format)
    click.echo(result)

@cli.command()
@click.pass_context
def init(ctx):
    """Initialize the database."""
    result = ctx.obj.init_db()
    click.echo(result)

@cli.command()
@click.pass_context
def version(ctx):
    """Show the application version."""
    click.echo(ctx.obj.get_version())

if __name__ == '__main__':
    cli()
