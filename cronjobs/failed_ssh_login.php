#!/usr/bin/php
<?php
// File: cronjobs/failed_ssh_login.php

chdir(dirname(__FILE__));
require_once "../include/db.php";

// Step 1: Run journalctl to get recent SSH login failures
$cmd = 'journalctl -u ssh.service --no-pager --since "1 hour ago"';
exec($cmd, $logLines, $exitCode);

if ($exitCode !== 0 || empty($logLines)) {
    echo "Failed to read journalctl output.\n";
    exit(1);
}

$ipSet = [];
$ipRegex = '/from ([0-9a-fA-F\.:]+)/';

foreach ($logLines as $line) {
    if (
        strpos($line, 'Failed password for') !== false ||
        strpos($line, 'Failed keyboard-interactive') !== false
    ) {
        if (preg_match($ipRegex, $line, $matches)) {
            $ip = trim($matches[1]);
            if ($ip !== '') {
                $ipSet[$ip] = true;
            }
        }
    }
}

// Step 2: Clear the table
$truncateQuery = "TRUNCATE TABLE failed_ips";
if ($conn->query($truncateQuery) === TRUE) {
    echo "Table successfully cleared.\n";
} else {
    echo "Error clearing table: " . $conn->error . "\n";
    exit(1);
}

// Step 3: Insert current IPs
$stmtInsert = $conn->prepare("INSERT INTO failed_ips (ip_address) VALUES (?)");

foreach (array_keys($ipSet) as $ip) {
    $stmtInsert->bind_param("s", $ip);
    $stmtInsert->execute();
}

$stmtInsert->close();
$conn->close();

echo "Current IPs successfully synced from journal.\n";
?>
