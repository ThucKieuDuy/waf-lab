<?php
session_start();

$host = getenv('DB_HOST') ?: 'waf_mysql_db';
$user = getenv('DB_USER') ?: 'root';
$pass = getenv('DB_PASSWORD') ?: (getenv('DB_ROOT_PASSWORD') ?: 'rootpass');
$dbname = getenv('DB_NAME') ?: 'vulnerable_db';

$conn = new mysqli($host, $user, $pass);

if ($conn->connect_error) {
    die("Kết nối CSDL thất bại: " . $conn->connect_error);
}

$conn->query("CREATE DATABASE IF NOT EXISTS $dbname");
$conn->select_db($dbname);

// Tạo bảng users & tài khoản admin/admin
$conn->query("CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    password VARCHAR(50) NOT NULL
)");

$result = $conn->query("SELECT * FROM users WHERE username='admin'");
if ($result->num_rows == 0) {
    $conn->query("INSERT INTO users (username, password) VALUES ('admin', 'admin')");
}

// Tạo bảng comments
$conn->query("CREATE TABLE IF NOT EXISTS comments (
    id INT AUTO_INCREMENT PRIMARY KEY,
    author VARCHAR(50) NOT NULL,
    content TEXT NOT NULL
)");

$result_c = $conn->query("SELECT * FROM comments");
if ($result_c->num_rows == 0) {
    $conn->query("INSERT INTO comments (author, content) VALUES ('System', 'Chào mừng bạn đã đăng nhập thành công vào hệ thống!')");
}
?>
