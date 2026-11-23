<?php
require_once 'db.php';

$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';

    // 🔴 LỖ HỔNG SQL INJECTION (Auth Bypass)
    $query = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";

    $result = $conn->query($query);

    if (!$result) {
        $error = "Lỗi CSDL SQL: " . $conn->error;
    } else if ($result->num_rows > 0) {
        $row = $result->fetch_assoc();
        $_SESSION['user'] = $row['username'];

        header("Location: comments.php");
        exit();
    } else {
        $error = "Sai tên đăng nhập hoặc mật khẩu!";
    }
}
?>
<!DOCTYPE html>
<html lang="vi">

<head>
    <meta charset="UTF-8">
    <title>Đăng nhập Hệ thống</title>
</head>

<body style="font-family: Arial; margin: 40px;">
    <h2>ĐĂNG NHẬP HỆ THỐNG</h2>
    <p><i>Tài khoản chuẩn: <b>admin / admin</b> (Hoặc sử dụng SQL Injection để bypass)</i></p>

    <?php if ($error): ?>
        <p style="color: red; font-weight: bold;"><?php echo $error; ?></p>
    <?php endif; ?>

    <form action="index.php" method="POST">
        <label>Username:</label><br>
        <input type="text" name="username" style="width: 250px; padding: 5px;"><br><br>
        <label>Password:</label><br>
        <input type="password" name="password" style="width: 250px; padding: 5px;"><br><br>
        <button type="submit" style="padding: 5px 15px;">Đăng nhập</button>
    </form>
</body>

</html>