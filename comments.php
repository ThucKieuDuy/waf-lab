<?php
require_once 'db.php';

if (!isset($_SESSION['user'])) {
    header("Location: index.php");
    exit();
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $author = $_SESSION['user'];
    $content = $_POST['content'] ?? '';

    // 🔴 LỖ HỔNG STORED XSS
    $stmt = $conn->prepare("INSERT INTO comments (author, content) VALUES (?, ?)");
    $stmt->bind_param("ss", $author, $content);
    $stmt->execute();

    header("Location: comments.php");
    exit();
}

$comments = $conn->query("SELECT * FROM comments ORDER BY id DESC");
?>
<!DOCTYPE html>
<html lang="vi">

<head>
    <meta charset="UTF-8">
    <title>Trang Quản trị & Bình luận</title>
</head>

<body style="font-family: Arial; margin: 40px;">
    <h2>Xin chào, <span style="color: blue;"><?php echo htmlspecialchars($_SESSION['user']); ?></span>!</h2>
    <p>Bạn đã đăng nhập thành công vào hệ thống bảo mật.</p>
    <hr>

    <h3>Danh sách Bình luận (XSS Test Area)</h3>
    <ul>
        <?php while ($c = $comments->fetch_assoc()): ?>
            <!-- 🔴 LỖ HỔNG XSS: Render trực tiếp HTML/JS -->
            <li><b><?php echo htmlspecialchars($c['author']); ?>:</b> <?php echo $c['content']; ?></li>
        <?php endwhile; ?>
    </ul>

    <hr>
    <h3>Gửi bình luận mới</h3>
    <form action="comments.php" method="POST">
        <textarea name="content" rows="4" cols="50" placeholder="Nhập nội dung bình luận..."></textarea><br><br>
        <button type="submit">Gửi bình luận</button>
    </form>
</body>

</html>