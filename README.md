# Failed SSH Login Tracker (Journalctl-Based)

A lightweight PHP-based system for tracking failed SSH login attempts on a Linux server.
It reads authentication failures directly from systemd-journal, extracts the source IP
addresses, and stores them in a MySQL/MariaDB database. A simple web interface displays
the most recent failed login IPs.

This is ideal for:

- Security dashboards
- Monitoring brute-force attempts
- Feeding IPs into firewalls or automation
- Lightweight intrusion visibility on minimal Ubuntu installs

---

## Features

- Reads SSH login failures directly from journalctl
- Supports IPv4 and IPv6
- Deduplicates IPs before storing
- Simple PHP cronjob for periodic updates
- Minimal web interface to display failed login IPs
- Works on systems without /var/log/auth.log (e.g., minimized Ubuntu)

---

## How it works

### 1. Cronjob script (cronjobs/failed_ssh_login.php)

- Runs:

        journalctl -u ssh.service --no-pager --since "1 hour ago"

- Scans for:
    - "Failed password for"
    - "Failed keyboard-interactive"

- Extracts IPv4/IPv6 addresses
- Deduplicates IPs
- Truncates the failed_ips table
- Inserts the current unique IPs

### 2. Web viewer (public/index.php)

- Connects to the database
- Fetches entries from failed_ips
- Displays one IP per line, newest first

---

## Installation

### 1. Install required packages

On Ubuntu/Debian:

    sudo apt update
    sudo apt install apache2 php php-mysql mariadb-server git

---

### 2. Clone the repository

    git clone https://gitlab.com/your/repo.git
    cd repo

Replace the URL with your actual GitLab repo.

---

### 3. Create the database

Log into MariaDB/MySQL:

    sudo mysql

Create the database and table:

    CREATE DATABASE ssh_monitor;

    USE ssh_monitor;

    CREATE TABLE failed_ips (
        id INT AUTO_INCREMENT PRIMARY KEY,
        ip_address VARCHAR(64) NOT NULL,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

Create a dedicated user:

    CREATE USER 'sshmon'@'localhost' IDENTIFIED BY 'yourpassword';
    GRANT ALL PRIVILEGES ON ssh_monitor.* TO 'sshmon'@'localhost';
    FLUSH PRIVILEGES;

---

### 4. Configure database connection

Edit include/db.php:

    <?php
    $servername = "localhost";
    $username = "sshmon";
    $password = "yourpassword";
    $dbname = "ssh_monitor";

    $conn = new mysqli($servername, $username, $password, $dbname);

    if ($conn->connect_error) {
        die("DB connection failed: " . $conn->connect_error);
    }
    ?>

Make sure this path matches your actual repo layout.

---

### 5. Test the cronjob script

From the repo root:

    php cronjobs/failed_ssh_login.php

Expected output:

    Table successfully cleared.
    Current IPs successfully synced from journal.

If you see "Failed to read journalctl output.", ensure:

- journalctl exists (usually at /usr/bin/journalctl)
- You’re on a systemd-based system
- You have permission to read the journal (root is safest)

---

### 6. Set up the cronjob

Edit root’s crontab:

    sudo crontab -e

Add:

    */5 * * * * /usr/bin/php /var/www/ssh_blocklist/cronjobs/failed_ssh_login.php >/dev/null 2>&1

This runs the script every 5 minutes.

---

### 7. Deploy the web viewer

Then visit in a browser:

    http://ssh.dmz.daygle.net

You should see:

- A list of IPs, one per line, if failed logins were found
- Or: "No failed login attempts found."

---

## Testing

### Generate a failed SSH login

From another machine (or a test host):

    ssh invaliduser@yourserver

Enter any password a few times to trigger failures.

Then run:

    php cronjobs/failed_ssh_login.php

Reload the web page — the source IP you used should now appear.

To verify the journal directly:

    journalctl -u ssh.service --since "5 minutes ago"

You should see lines containing "Failed password for" and the same IP.

---

## Project structure

    repo/
    ├── cronjobs/
    │   └── failed_ssh_login.php
    ├── include/
    │   └── db.php
    ├── public/
    │   └── index.php
    └── README.md

Adjust names/paths if your repo layout differs.

---

## Security notes

- Web output uses htmlspecialchars() to avoid XSS
- Limit access to the web viewer (e.g., HTTP auth, VPN, IP allowlist)
- Store include/db.php with restrictive permissions, for example:

        chmod 640 include/db.php
        chown www-data:www-data include/db.php    # or your web user

- The script only reads from journalctl and writes to your DB; it doesn’t modify system auth config


