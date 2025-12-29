# Failed SSH Login Tracker (Journalctl-Based)

A lightweight PHP-based system for tracking **failed SSH login attempts** on a Linux server.  
It reads authentication failures directly from **systemd-journal**, extracts the source IP addresses, and stores them in a MySQL/MariaDB database.  
A simple web interface displays the most recent failed login IPs.

This is ideal for:

- Security dashboards  
- Monitoring brute-force attempts  
- Feeding IPs into firewalls or automation  
- Lightweight intrusion visibility on minimal Ubuntu installs  

---

## Features

- Reads SSH login failures directly from `journalctl`
- Supports IPv4 and IPv6
- Deduplicates IPs before storing
- Simple PHP cronjob for periodic updates
- Minimal web interface to display failed login IPs
- Works on systems without `/var/log/auth.log` (e.g., minimized Ubuntu)

---

## How It Works

### 1. Cronjob Script (`cronjobs/failed_ssh_login.php`)
- Runs:  
  `journalctl -u ssh.service --no-pager --since "1 hour ago"`
- Extracts IPs from failed SSH login attempts
- Clears the `failed_ips` table
- Inserts the current list of failed IPs

### 2. Web Viewer (`public/index.php`)
- Connects to the database
- Displays the list of failed IPs
- Sorted by timestamp (latest first)

---

## Installation

### 1. Install Required Packages

```bash
sudo apt update
sudo apt install php php-mysql mariadb-server git