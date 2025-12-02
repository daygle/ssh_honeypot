<?php
// File: include/db.example.php

// Replace with your actual database credentials
$host = 'mysql.dmz.daygle.net';
$username = 'ssh_blocklist';
$password = 'Secret_Password!';
$database = 'ssh_blocklist';

// Create a database connection
$conn = new mysqli($host, $username, $password, $database);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}
?>
