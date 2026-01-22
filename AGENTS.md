# AGENTS.md

## Architectural Overview

Netprobe is composed of three main components:

*   **Agent**: A lightweight process that runs on a host within the network to be monitored. It periodically contacts the server to get a list of tasks, such as SNMP probes or Nmap scans. The agent then executes these tasks and sends the results back to the server.
*   **Server**: A FastAPI-based web service that provides a REST API for agents to communicate with. It is responsible for storing and managing the network topology data, as well as providing a central point of configuration for the agents.
*   **CLI**: A command-line interface that allows users to interact with the server. It can be used to configure the system, manage nodes and networks, and generate reports.
