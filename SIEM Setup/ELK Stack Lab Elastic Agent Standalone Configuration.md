## 📄 ELK Stack Lab: Elastic Agent Standalone Configuration

This document summarizes the steps taken to install and configure the Elastic Agent in standalone mode on `labserver` and integrate it with the self-managed Elasticsearch and Kibana instance.

### 1\. Environment and Goal

  * **Host:** `labserver` (Ubuntu/Debian)
  * **Elastic Stack Version:** 8.19.7 (or similar)
  * **Goal:** Configure the Elastic Agent to collect core system metrics and logs, plus high-value security logs, without using Fleet.

### 2\. Elastic Agent Standalone Configuration (`elastic-agent.yml`)

The agent was configured by editing `/opt/Elastic/Agent/elastic-agent.yml`. The core configuration blocks added or modified are detailed below:

#### **A. Auditd Log Collection (Filebeat)**

This block enables the collection of all security events written by the Linux Auditing System (`auditd`).

```yaml
  # Collecting Auditd logs
  - type: filestream
    id: auditd-log-input
    data_stream.namespace: default
    use_output: default
    streams:
      - id: auditd-filestream-stream
        data_stream:
          dataset: auditd
        paths:
          # Standard location for auditd logs
          - /var/log/audit/audit.log
```

  * **Kibana Data View:** `logs-auditd-*`

#### **B. Authentication Log Collection (Filebeat)**

This block captures authentication-related events such as SSH logins, `sudo` usage, and user activity.

```yaml
  # Collecting Authentication Logs (SSH, Sudo, User Activity)
  - type: filestream
    id: auth-log-input
    data_stream.namespace: default
    use_output: default
    streams:
      - id: auth-filestream-stream
        data_stream:
          dataset: auth
        paths:
          # Standard location for authentication logs on Debian/Ubuntu
          - /var/log/auth.log
```

  * **Kibana Data View:** `logs-auth-*`

#### **C. Network Socket Metrics (Metricbeat)**

This block was added to collect detailed TCP and UDP network traffic statistics. The initial attempt failed due to an incorrect metricset name (`tcp`/`udp`) and was corrected to use the comprehensive **`socket`** metricset.

```yaml
  # Collecting system metrics (Modified Block)
  - type: system/metrics
    id: unique-system-metrics-input
    data_stream.namespace: default
    use_output: default
    streams:
      # ... (Existing metricsets: cpu, memory, network, filesystem)

      # Network Socket Metricset (Corrected input for TCP/UDP statistics)
      - metricsets:
        - socket
        data_stream.dataset: system.socket
```

  * **Kibana Data View:** `metrics-system.socket-*`

### 3\. Data Streams and Verification Summary

The lab environment is confirmed to be successfully collecting the following five data streams, which can be verified in Kibana's **Discover** tab:

| Integration Type | Data Stream | Description | Status |
| :--- | :--- | :--- | :--- |
| **Default System** | `logs-system.syslog-*` | Linux system messages | **Working** |
| **System Metrics** | `metrics-system.cpu-*`, etc. | CPU, Memory, Disk, Network I/O | **Working** |
| **Security Log** | `logs-auditd-*` | Audit daemon events (e.g., file access, commands) | **Working** |
| **Security Log** | `logs-auth-*` | Authentication attempts (SSH, failed logins) | **Working** |
| **Network Metrics** | `metrics-system.socket-*` | Detailed TCP/UDP connection and traffic stats | **Working** |

