### VPN_Setup_Journey.md

```markdown
# VPN Setup Journey: OpenVPN to SoftEther on Ubuntu 24.04

This document chronicles the process of setting up a self-hosted VPN on an Ubuntu 24.04.3 LTS (Noble Numbat) lab server, starting with OpenVPN Access Server and pivoting to SoftEther VPN due to compatibility issues. It details progress, errors, solutions, and lessons learned, demonstrating hands-on cybersecurity skills for my career transition, aligned with certifications like ISC2 CC and Google Cybersecurity Professional.

## Objective
Set up a secure, open-source VPN server in a home lab to practice network security, remote access, and system administration. The VPN should support OpenVPN clients for compatibility with tools like Kali Linux and integrate with Wazuh/Suricata for monitoring.

## Environment
- **OS**: Ubuntu 24.04.3 LTS (Noble Numbat)
- **Server IP**: [ip]
- **Tools**: Wazuh, Suricata, Elastic, Wireshark, Auditd
- **SSH Port**: 2222 (non-standard)
- **Certifications**: ISC2 CC, Google Cybersecurity Professional, pursuing CompTIA Security+

## Progress and Issues

### Phase 1: OpenVPN Access Server Setup
**Goal**: Install and configure OpenVPN Access Server for remote access.

#### Attempted Steps
1. Added OpenVPN repository for Ubuntu 24.04:
   ```bash
   echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/as-repository.asc] http://as-repository.openvpn.net/as/debian noble main" | sudo tee /etc/apt/sources.list.d/openvpn-as-repo.list
   ```
2. Imported GPG key:
   ```bash
   curl -fsSL https://as-repository.openvpn.net/as-repo-public.gpg | sudo tee /etc/apt/keyrings/as-repository.asc
   ```
3. Installed OpenVPN:
   ```bash
   sudo apt update
   sudo apt install openvpn-as -y
   ```

#### Issues Encountered
1. **GPG Error**:
   - Error: `W: GPG error: http://packages.openvpn.net/as/debian noble InRelease: Unknown error executing apt-key`.
   - Cause: Deprecated `apt-key` usage in Ubuntu 24.04.
   - Solution: Used binary GPG key in `/etc/apt/keyrings`:
     ```bash
     curl -fsSL https://as-repository.openvpn.net/as-repo-public.gpg | sudo gpg --dearmor -o /etc/apt/keyrings/as-repository.gpg
     ```

2. **Package Not Found**:
   - Error: `E: Unable to locate package openvpn-as`.
   - Cause: Ubuntu 24.04 (noble) not supported by OpenVPN repository.
   - Solution: Tried Ubuntu 22.04 (jammy) and 20.04 (focal) repositories:
     ```bash
     echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/as-repository.gpg] http://as-repository.openvpn.net/as/debian focal main" | sudo tee /etc/apt/sources.list.d/openvpn-as-repo.list
     ```

3. **Dependency Error**:
   - Error: `openvpn-as : Depends: libssl1.1 (>= 1.1.1) but it is not installable`.
   - Cause: Ubuntu 24.04 uses `libssl3`, not `libssl1.1`.
   - Solution: Installed `libssl1.1` from Ubuntu 20.04 repository:
     ```bash
     echo "deb http://security.ubuntu.com/ubuntu focal-security main" | sudo tee /etc/apt/sources.list.d/focal-security.list
     sudo apt install libssl1.1 -y
     ```

4. **Python Bad Magic Number**:
   - Error: `zipimport.ZipImportError: bad magic number in 'pyovpn': b'U\r\r\n'`.
   - Cause: OpenVPN’s `pyovpn-2.0-py2.7.egg` required Python 2.7, incompatible with Ubuntu 24.04’s Python 3.12.
   - Solutions Tried:
     - Installed Python 3.10 and 3.8:
       ```bash
       sudo apt install python3.10 python3.10-venv python3.10-dev -y
       sudo apt install python3.8 python3.8-venv python3.8-dev -y
       ```
     - Cleared bytecode and updated shebang:
       ```bash
       sudo find /usr/local/openvpn_as -name "*.pyc" -delete
       sudo sed -i 's/#!\/usr\/bin\/python3/#!\/usr\/bin\/python3.8/' /usr/local/openvpn_as/bin/_ovpn-init
       ```
     - Attempted Python 2.7, but failed due to package conflicts:
       ```bash
       sudo apt install python2.7 -y
       ```
   - Outcome: Persistent errors led to abandoning OpenVPN.

5. **Missing User and Scripts**:
   - Errors: `passwd: user 'openvpn' does not exist`, `sudo: /usr/local/openvpn_as/bin/ovpn-passwd: command not found`.
   - Cause: Incomplete installation due to compatibility issues.
   - Outcome: Confirmed OpenVPN was unsuitable for Ubuntu 24.04.

**Decision**: Pivoted to SoftEther VPN, which supports Ubuntu 24.04 natively and avoids Python dependencies.

### Phase 2: SoftEther VPN Setup
**Goal**: Install and configure SoftEther VPN for OpenVPN-compatible remote access.

#### Attempted Steps
1. Downloaded SoftEther:
   ```bash
   wget https://github.com/SoftEtherVPN/SoftEtherVPN_Stable/releases/download/v4.43-9799-beta/softether-vpnserver-v4.43-9799-beta-2023.08.31-linux-x64-64bit.tar.gz
   tar xzf softether-vpnserver-v4.43-9799-beta-2023.08.31-linux-x64-64bit.tar.gz
   cd vpnserver
   ```
2. Compiled and installed:
   ```bash
   make
   sudo mv vpnserver /usr/local/
   sudo chmod 755 /usr/local/vpnserver/*
   ```
3. Started server:
   ```bash
   sudo /usr/local/vpnserver/vpnserver start
   ```

#### Issues Encountered
1. **Compilation Error**:
   - Error: `make[1]: gcc: No such file or directory`.
   - Cause: Missing GCC and build tools.
   - Solution: Installed dependencies:
     ```bash
     sudo apt install -y build-essential gcc make libssl-dev zlib1g-dev libncurses5-dev libncursesw5-dev libreadline-dev libffi-dev libsqlite3-dev libbz2-dev liblzma-dev tk-dev uuid-dev
     ```

2. **Directory Error**:
   - Error: `chmod: cannot access '/usr/local/vpnserver/*': Not a directory`.
   - Cause: Incorrect `mv` command created a file instead of a directory.
   - Solution: Recompiled and moved the entire directory:
     ```bash
     sudo rm /usr/local/vpnserver
     cd ~/vpnserver
     make clean
     make
     sudo mv ~/vpnserver /usr/local/vpnserver
     ```

3. **Virtual Hub Error**:
   - Error: `The specified Virtual Hub does not exist on the server`.
   - Cause: Attempted to select `VPNHUB` before creating it.
   - Solution: Used Server Admin Mode to create `VPNHUB`:
     ```bash
     sudo /usr/local/vpnserver/vpncmd
     ```

4. **Config Generation Error**:
   - Error: `The parameter "/tmp/softether.ovpn" has been specified. It is not possible to specify this parameter`.
   - Cause: `OpenVpnMakeConfig` doesn’t accept file paths.
   - Solution: Generated ZIP file:
     ```bash
     OpenVpnMakeConfig
     ```
     Extracted:
     ```bash
     sudo unzip /tmp/softether_openvpn.zip -d /tmp/
     sudo mv /tmp/labserver_openvpn_remote_access_l3.ovpn /tmp/softether.ovpn
     ```

5. **SCP Errors**:
   - Errors: `ssh: connect to host [ip] port 22: Connection refused`, `Connection timed out`.
   - Cause: SSH on lab server uses port 2222, not 22; incorrect IP used.
   - Solution: Used local testing since client is on the same machine.

#### Final Configuration
- Created virtual hub `VPNHUB` and user `[username]`:
  ```bash
  HubCreate VPNHUB
  Hub VPNHUB
  UserCreate [username]
  UserPasswordSet [username]
  SecureNatEnable
  OpenVpnEnable yes /PORTS:1194
  ```
- Generated OpenVPN config:
  ```bash
  OpenVpnMakeConfig
  ```

### Phase 3: Client Testing
**Status**: Config file `/tmp/softether.ovpn` is ready for testing.

#### Next Steps
1. Test client on Ubuntu laptop:
   ```bash
   sudo apt install openvpn -y
   sudo openvpn --config /tmp/softether.ovpn
   curl ifconfig.me
   ```
2. Set up Systemd service:
   ```bash
   sudo nano /etc/systemd/system/softether-vpnserver.service
   sudo systemctl enable softether-vpnserver
   sudo systemctl start softether-vpnserver
   ```

### Persistent Issues
- **APT Permission Warnings**:
  - Error: `W: Unable to read /etc/apt/sources.list.d/ookla_speedtest-cli.list`.
  - Solution:
    ```bash
    sudo chmod 644 /etc/apt/sources.list.d/*.list
    sudo chown root:root /etc/apt/sources.list.d/*.list
    sudo apt update
    ```

### Lessons Learned
- **Compatibility Matters**: OpenVPN’s reliance on Python 2.7 and `libssl1.1` made it incompatible with Ubuntu 24.04, highlighting the importance of checking OS support.
- **Troubleshooting Skills**: Addressed GPG, dependency, and Python errors, reinforcing problem-solving for package management.
- **Pivoting Solutions**: Switching to SoftEther demonstrated adaptability when faced with intractable issues.
- **Documentation**: Detailed logging of errors and solutions is critical for portfolio building and interview prep.

### Cybersecurity Relevance
- **Network Security**: Configured firewall rules (`ufw`) to secure VPN ports.
- **System Administration**: Managed package dependencies and system services.
- **Monitoring**: Planned integration with Wazuh/Suricata for log analysis, aligning with SOC analyst skills.

### Next Steps
- Test VPN client connection and verify routing.
- Integrate with Wazuh/Suricata for monitoring:
  ```bash
  sudo nano /var/ossec/etc/ossec.conf
  sudo systemctl restart wazuh-agent
  ```


This document reflects my hands-on experience in a cybersecurity lab, showcasing skills for my career transition.
```