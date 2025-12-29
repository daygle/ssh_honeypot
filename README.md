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
    sudo apt install apache2 php php-mysql libapache2-mod-php mariadb-server git

---

### 2. Clone the repository

    cd /var/www/
    git clone https://gitlab.com/daygle/ssh_blocklist.git

---

### 3. Create the database

Log into MariaDB/MySQL:

    sudo mysql

Create the database:

    CREATE DATABASE ssh_blocklist;
    EXIT;

Import the schema from the repository:

    mysql -u root ssh_blocklist < sql/initial_schema.sql

This will create the `failed_ips` table with the following structure:

- `id` (auto‑increment primary key)  
- `ip_address` (VARCHAR(45), UNIQUE)  
- `timestamp` (DATETIME, defaults to CURRENT_TIMESTAMP)

---

### 4. Configure database connection

Edit `include/db.php` and set your database credentials:

    <?php
    $servername = "localhost";
    $username = "ssh_blocklist";
    $password = "yourpassword";
    $dbname = "ssh_blocklist";

    $conn = new mysqli($servername, $username, $password, $dbname);

    if ($conn->connect_error) {
        die("DB connection failed: " . $conn->connect_error);
    }
    ?>

Make sure the database name matches the one you created (`ssh_blocklist`).

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

    */5 * * * * /usr/bin/php /var/www/ssh_blocklist/cronjobs/failed_ssh_login.php > /dev/null 2>&1

This runs the script every 5 minutes.
