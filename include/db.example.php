<?php
// File: include/db.example.php

// Replace with your actual database credentials
$host = 'mysql.daygle';
$username = 'daygle-ssh';
$password = 'Secret_Password!';
$database = 'daygle-ssh';

// Create a database connection
$conn = new mysqli($host, $username, $password, $database);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}
?>
