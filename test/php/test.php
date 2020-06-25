<?php

$conn = mysqli_init();
$conn->real_connect("127.0.0.1", "root", "root");
$conn->options(MYSQLI_OPT_LOCAL_INFILE, true);
$conn->query("SELECT 1");

$pdo = new PDO("mysql:host=127.0.0.1;dbname=test;", "root", "root", [
            PDO::MYSQL_ATTR_LOCAL_INFILE => true,
        ]);
$pdo->query("SELECT 2");
