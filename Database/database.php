<?php

$servername = "localhost"; // Địa chỉ máy chủ cơ sở dữ liệu
$username = "root"; // Tên người dùng cơ sở dữ liệu
$password = ""; // Mật khẩu cơ sở dữ liệu
$dbname = "scamweb"; // Tên cơ sở dữ liệu
$port = 3306; // Cổng kết nối cơ sở dữ liệu (mặc định là 3306 cho MySQL)

// Tạo kết nối
$conn = new mysqli($servername, $username, $password, $dbname, $port);

// Kiểm tra kết nối
if ($conn->connect_error) {
    echo "Kết nối thất bại: " . $conn->connect_error;
    die("Kết nối thất bại: " . $conn->connect_error);
}
?>