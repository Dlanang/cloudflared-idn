# Project README

This project is a web application with a microservices-based architecture, orchestrated using Docker Compose. It includes a Python backend, a React frontend, and various other services for reverse proxying, security, and data visualization.

## Project Structure

- **`backend/`**: The core Python backend application.
  - `app/main.py`: The main application logic.
  - `Dockerfile`: For building the backend Docker image.
  - `requirements.txt`: Python dependencies.

- **`caddy/`**: Caddy web server configuration.
  - `Caddyfile`: Caddy configuration file for reverse proxying and handling web traffic.

- **`cloudflared/`**: Cloudflare Tunnel configuration.
  - `config.yml`: Configuration for `cloudflared` to expose the application to the internet securely.

- **`frontend/`**: The React-based frontend application.
  - `src/`: Source code for the React application.
    - `App.jsx`: The main React component.
    - `main.jsx`: The entry point for the frontend application.
  - `vite.config.js`: Configuration for the Vite build tool.
  - `tailwind.config.js`: Configuration for Tailwind CSS.
  - `Dockerfile`: For building the frontend Docker image.

- **`scripts/`**: A collection of utility scripts for managing the project.
  - Contains various `.sh` scripts for deployment, setup, and maintenance tasks.

- **`streamlit/`**: A Streamlit application.
  - `app/app.py`: The Streamlit application code, likely for data visualization or interactive dashboards.
  - `Dockerfile`: For building the Streamlit Docker image.

- **`suricata/`**: Suricata Intrusion Detection System (IDS) configuration.
  - `suricata.yaml`: The main configuration file for Suricata.
  - `Dockerfile.suricata`: For building the Suricata Docker image.

- **`docker-compose.yml`**: The main Docker Compose file for orchestrating all the services.

## Getting Started

To run the project, you will need to have Docker and Docker Compose installed. Then, you can run the following command:

```bash
docker-compose up -d
```

This will start all the services in the background.

## Security

For security reasons, it is highly recommended to change the default credentials. The default credentials are provided in the following files:

- `caddy/.auth.hashes`
- `backend/creds.json`

## Ignored Files

This project contains a `.gitignore` file that is configured to ignore files and directories that are not necessary for the repository. This includes:

- `node_modules/`
- `.env`
- `*.log`
- `*.bak*`
- `pnpm-lock.yaml`
- `pnpm-workspace.yaml`
- and other common files.
