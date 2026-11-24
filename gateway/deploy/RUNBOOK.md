# Project ATLAS Gateway — Oracle Cloud Always Free VM Deployment Runbook

This runbook deploys `gateway/` behind Caddy HTTPS termination on an Oracle Cloud Infrastructure (OCI) Always Free Ubuntu Linux VM. The Node.js gateway listens only on `127.0.0.1:8443`; Caddy listens on public port `443` and handles TLS certificates automatically.

> **Optional Security Tools Note:** `gateway/deploy/install-tools.sh` installs only `nmap` and `tshark`. Additional probes shown in `/api/v1/tools` (`wireshark`, `zeek`, `suricata`, `osquery`, and `yara`) are optional and require separate manual installation and configuration outside this script.

---

### a. Create an Oracle Cloud Always Free VM

1. Sign in to the OCI Console and open **Compute -> Instances -> Create instance**.
2. Choose **Ubuntu 24.04 LTS** (or **Ubuntu 22.04 LTS**) as the image.
3. Under **Shape**, select an **Always Free-eligible** shape — for example **`VM.Standard.A1.Flex`** (Ampere Arm64, 1–4 OCPUs, 6–24 GB RAM) or **`VM.Standard.E2.1.Micro`** (AMD x86_64, 1 OCPU, 1 GB RAM).
   - *Capacity note:* Always Free capacity (especially `VM.Standard.A1.Flex`) may be temporarily unavailable in some OCI home regions or availability domains. Try switching Availability Domains within your home region or starting with `VM.Standard.E2.1.Micro` if capacity is constrained.
4. Assign a public IPv4 address, upload your SSH public key, and launch the instance.
5. SSH into the instance as `ubuntu`:
   ```bash
   ssh ubuntu@<VM_PUBLIC_IP>
   ```

---

### b. Open Only Ports 22 and 443 in the OCI Network Security List

1. In the OCI Console, open the instance's VCN -> **Subnet** -> **Security List** (or attached **Network Security Group**).
2. Ensure **Ingress Rules** permit **only**:
   - **TCP port `22`** (SSH — restrict source CIDR to your operator IP if possible)
   - **TCP port `443`** (HTTPS for Caddy)
3. **Do NOT open port `8443`** or any other port for the Node.js gateway. Wait: port `80` is only needed if you use HTTP-01 ACME challenges, whereas Caddy automatically obtains certificates via TLS-ALPN-01 on port `443` alone when port `443` is open.

---

### c. Point a Domain Name at the VM and Confirm with `dig`

1. At your DNS provider, create an **A record** pointing the domain name you want to use to `<VM_PUBLIC_IP>` (and an `AAAA` record if IPv6 is enabled).
2. Confirm DNS propagation from your workstation or the VM before starting Caddy:
   ```bash
   dig +short <the domain you configured in step c> A
   ```
   Verify the returned IP matches `<VM_PUBLIC_IP>`.

---

### d. Install Node.js 20+, Caddy, and the Required Tools

Run the following as `root` (or with `sudo`) on the VM:

1. **Install Node.js 22 LTS** (satisfies Node 20+):
   ```bash
   sudo apt-get update
   sudo apt-get install -y ca-certificates curl gnupg git debian-keyring debian-archive-keyring apt-transport-https
   curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
   sudo apt-get install -y nodejs
   node -v
   ```
2. **Install Caddy** from the official Caddy apt repository:
   ```bash
   curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
   curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
   sudo apt-get update
   sudo apt-get install -y caddy
   ```
3. **Install `nmap` and `tshark`** (after cloning the repository in step e, or run the helper script directly once cloned):
   ```bash
   sudo bash /opt/atlas/gateway/deploy/install-tools.sh
   ```
   *(If you run steps d and e together, clone the repository first so `/opt/atlas/gateway/deploy/install-tools.sh` is present on disk.)*

---

### e. Clone the Repository, Install Dependencies, and Build the Gateway

1. Clone the repository into `/opt/atlas` and set directory ownership:
   ```bash
   sudo git clone <YOUR_REPOSITORY_URL> /opt/atlas
   cd /opt/atlas/gateway
   ```
2. Run a clean dependency install and TypeScript build:
   ```bash
   sudo npm ci
   sudo npm run build
   ```
3. Confirm the compiled entrypoint exists:
   ```bash
   ls -l /opt/atlas/gateway/dist/src/server.js
   ```
4. If you did not run the tools script in step d yet, run it now and verify `nmap` and `tshark` are on `PATH`:
   ```bash
   sudo bash /opt/atlas/gateway/deploy/install-tools.sh
   ```

---

### f. Create `/etc/atlas-gateway/env` with Mode `0640`

1. Create the dedicated non-root `atlas-gateway` user, config directory, and writable sandbox directory:
   ```bash
   sudo useradd --system --no-create-home --shell /usr/sbin/nologin atlas-gateway
   sudo mkdir -p /etc/atlas-gateway /var/lib/atlas-gateway
   sudo chown atlas-gateway:atlas-gateway /var/lib/atlas-gateway
   sudo chmod 0750 /var/lib/atlas-gateway
   ```
2. Copy the environment template and lock down ownership and permissions:
   ```bash
   sudo cp /opt/atlas/gateway/.env.example /etc/atlas-gateway/env
   sudo chown root:atlas-gateway /etc/atlas-gateway/env
   sudo chmod 0640 /etc/atlas-gateway/env
   ```
3. Edit `/etc/atlas-gateway/env` (`sudo chmod 0640` keeps it readable only by `root` and `atlas-gateway`):
   - Set `GATEWAY_HOST=127.0.0.1` and `GATEWAY_PORT=8443`
   - Set `GATEWAY_WORK_DIR=/var/lib/atlas-gateway`
   - Set `GATEWAY_CORS_ORIGIN` to your Project ATLAS frontend origin (`https://...`)
   - Set `SUPABASE_URL`, `SUPABASE_ANON_KEY`, `SUPABASE_JWT_ISSUER`, `SUPABASE_JWT_AUDIENCE=authenticated`, and `SUPABASE_JWKS_URL` (never place `SUPABASE_SERVICE_ROLE_KEY` in this file)
   - If using self-hosted HS256 JWT verification instead of JWKS, generate the secret directly on the VM with `openssl rand -hex 32` rather than reusing sample strings
   - Set `GATEWAY_TARGET_ALLOWLIST` to your authorised target CIDRs/domains (keep empty if no active scan targets are authorised)
   - Set `ATLAS_GATEWAY_DOMAIN` to **the domain you configured in step c**
   - Optionally populate free CTI proxy keys (`OTX_API_KEY`, `ABUSECH_AUTH_KEY`, `MISP_URL`/`MISP_API_KEY`, `TAXII_API_ROOT`/`TAXII_COLLECTION_ID`) on the VM as needed

---

### g. Install the Systemd Service and Caddyfile, Then Start Both

1. Install the systemd unit for the gateway:
   ```bash
   sudo cp /opt/atlas/gateway/deploy/atlas-gateway.service /etc/systemd/system/atlas-gateway.service
   ```
2. Install the Caddyfile and configure Caddy's systemd service to load `/etc/atlas-gateway/env` (so `{$ATLAS_GATEWAY_DOMAIN}` is defined):
   ```bash
   sudo cp /opt/atlas/gateway/deploy/Caddyfile /etc/caddy/Caddyfile
   sudo mkdir -p /etc/systemd/system/caddy.service.d
   printf '[Service]\nEnvironmentFile=/etc/atlas-gateway/env\n' | sudo tee /etc/systemd/system/caddy.service.d/atlas-env.conf
   ```
   Validate the Caddyfile syntax using the environment file:
   ```bash
   sudo bash -c 'set -a && source /etc/atlas-gateway/env && caddy validate --config /etc/caddy/Caddyfile'
   ```
3. Reload systemd, enable, and start both services:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now atlas-gateway caddy
   sudo systemctl status atlas-gateway caddy --no-pager
   ```

---

### h. Verify `GET /health` Returns `READY`

Using a valid Supabase AAL2 user Bearer JWT and workspace organisation ID from your Project ATLAS session:

```bash
curl -fsS \
  -H "Authorization: Bearer <YOUR_AAL2_ACCESS_TOKEN>" \
  -H "x-atlas-org-id: <YOUR_ORG_UUID>" \
  "https://<the domain you configured in step c>/health"
```

Confirm HTTP `200` with `"status": "READY"`, your authenticated org/role context, `tools[]`, and `ctiSources[]`.

---

### i. Verify Unauthenticated `GET /api/v1/tools` Returns `401`

Run an unauthenticated request against `/api/v1/tools` and inspect the HTTP status line:

```bash
curl -i "https://<the domain you configured in step c>/api/v1/tools"
```

Confirm the gateway fails closed and returns **`HTTP/2 401`** (or `HTTP/1.1 401`).

---

### j. Enable `ufw` Allowing Only Ports 22 and 443

Configure the host firewall on the VM so only SSH (`22`) and HTTPS (`443`) are exposed externally:

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp
sudo ufw allow 443/tcp
sudo ufw --force enable
sudo ufw status verbose
```

Confirm `8443` is not listed as allowed and that `ss -tlnp | grep 8443` shows `127.0.0.1:8443` only.

---

### k. Configure Unattended Security Updates

Enable automatic Debian/Ubuntu security patching on the VM:

```bash
sudo apt-get update
sudo apt-get install -y unattended-upgrades apt-listchanges
sudo dpkg-reconfigure -plow unattended-upgrades
```

Verify the periodic timer and configuration:

```bash
cat /etc/apt/apt.conf.d/20auto-upgrades
sudo unattended-upgrades --dry-run --debug
```
