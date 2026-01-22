# Netprobe

Netprobe is a network topology discovery and analysis tool. It consists of an agent, a server, and a CLI.

Note: This project is currently under development.
Not all features have been implemented

## Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/infologicmgmt/netprobekit
    cd netprobekit
    ```

2.  **Install dependencies:**
    It is recommended to use a virtual environment.
    ```bash
    python -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
    ```
    **Note:** If you plan to use a PostgreSQL or MySQL database, you will need to install the appropriate database drivers separately. For example:
    ```bash
    pip install psycopg2-binary
    # or
    pip install mysqlclient
    ```

3.  **Initialize the database:**
    Before running the server for the first time, you need to apply the database migrations.
    ```bash
    alembic upgrade head
    ```

## Configuration

1.  **Copy the example configuration files:**
    ```bash
    cp conf/config-example.yaml conf/config.yaml
    cp conf/dotenv-example conf/.env
    ```

2.  **Edit the configuration:**
    *   `conf/config.yaml`: Adjust server, agent, and logging settings as needed.
    *   `conf/.env`: Set the `NETPROBE_API_KEY` for secure communication between the components. If you are using a database that requires a password, set the `DATABASE_PASSWORD` as well.

## Usage

```bash
# Show the current configuration
netprobe show-config

# Generate a switch port mapping report
netprobe report switchport --format csv
```
