<?php
session_start();
require_once '../Database/database.php';

/* =========================
CHECK IF USER ALREADY LOGIN
========================= */

if(isset($_SESSION['user_id'])){

    if($_SESSION['role']=="Admin"){
        header("Location: ../admin/admin_dashboard.php");
        exit;
    }else{
        header("Location: index.php");
        exit;
    }

}

$error = "";

//php nằm ở phía Backend
//Nếu dữ liệu tồn tại
if($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST["username"]) && isset($_POST["password"])) {

    $username = trim($_POST["username"]);
    $password = $_POST["password"];

    //Lấy IP và Browser
    $ip = $_SERVER['REMOTE_ADDR'];
    $browser = $_SERVER['HTTP_USER_AGENT'];

    try {

        $sql_query = "SELECT * FROM users WHERE username = ? LIMIT 1"; //Khai báo câu query (kiểu dữ liệu string)

        $stmt = $conn->prepare($sql_query); //Chuẩn bị câu truy vấn, biến đổi string thành câu truy vấn an toàn

        $stmt->bind_param("s", $username); //truyền vào các giá trị tương ứng

        $stmt->execute(); //Thực thi câu truy vấn đã chuẩn bị sẵn

        $result = $stmt->get_result(); //Lấy kết quả truy vấn


        if ($result->num_rows > 0) {

            $user = $result->fetch_assoc(); //chuyển đổi kết quả thành mảng kết hợp

            if (password_verify($password, $user['password'])) {

                $user_id = $user['id'];
                $user_name = $user['username'];
                $role = $user['role'];

                //Lưu session
                $_SESSION['user_id'] = $user_id;
                $_SESSION['user_name'] = $user_name;
                $_SESSION['role'] = $role;
                //Update trạng thái đăng nhập
                $stmt = $conn->prepare("UPDATE users SET status='Active', last_login=NOW() WHERE id=?");
                $stmt->bind_param("i",$user_id);
                $stmt->execute();


                /* INSERT ACTIVITY LOG (LOGIN SUCCESS) */

                $stmt = $conn->prepare("
                INSERT INTO activity_logs
                (user_id,username,role,action,target,ip_address,user_agent)
                VALUES (?,?,?,?,?,?,?)
                ");

                $action = "Login Success";
                $target = $username;

                $stmt->bind_param(
                "issssss",
                $user_id,
                $user_name,
                $role,
                $action,
                $target,
                $ip,
                $browser
                );

                $stmt->execute();


                /* REDIRECT USER */

                if($role == "Admin"){

                    header("Location: Admin/admin_dashboard.php");
                    exit;

                }else{

                    header("Location: index.php");
                    exit;

                }

            }
            
            else {

                $error = "Wrong password.";

            }

        }
        else {

            $error = "Username or password is incorrect.";

        }

    }
    catch (Exception $e) {

        echo "Login error: " . $e->getMessage();

    }

}
?>


<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.7/dist/css/bootstrap.min.css" rel="stylesheet">

    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css">

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.7/dist/js/bootstrap.bundle.min.js"></script>

    <title>Login</title>
    <style>
    body {
        background-image: url("img/background.png");
        background-size: cover;
        background-position: center;
        height: 100vh;
        display: flex;
        justify-content: center;
        align-items: center;
    }

    .overlay {
        position: absolute;
        width: 100%;
        height: 100%;
        background: rgba(0, 0, 0, 0.6);
        display: flex;
        justify-content: center;
        align-items: center;
        color: white;
    }

    .login-box {
        width: 500px;
        background: rgba(0, 0, 0, 0.6);
        padding: 35px;
        border-radius: 12px;
        box-shadow: 0 10px 25px rgba(0, 0, 0, 0.4);
    }

    .links {
        display: flex;
        justify-content: space-between;
        margin-top: 15px;
        font-size: 14px;
    }
    </style>

</head>

<body>

    <div class="overlay">

        <div class="login-box">

            <h3 class="text-center mb-4">Login</h3>

            <?php if(!empty($error)){ ?>
            <div class="alert alert-danger text-center">
                <?php echo $error ?>
            </div>
            <?php } ?>

            <form method="POST">

                <div class="mb-3">

                    <label class="form-label">Username</label>

                    <input type="text" class="form-control" name="username" required>

                </div>

                <div class="mb-3">

                    <label class="form-label">Password</label>

                    <div class="input-group">

                        <input type="password" class="form-control" id="password" name="password" required>

                        <span class="input-group-text" onclick="togglePassword('password',this)">
                            <i class="bi bi-eye"></i>
                        </span>

                    </div>

                </div>

                <div class="d-flex justify-content-between mt-3">

                    <button type="submit" class="btn btn-primary">
                        Login
                    </button>

                    <a href="index.php" class="btn btn-secondary">
                        Back
                    </a>

                </div>

            </form>

            <div class="links">

                <a href="register.php">Don't have an account? Register here</a>

                <a href="forgot_password.php">Forgot Password?</a>

            </div>

        </div>

    </div>

    <script>
    function togglePassword(fieldId, icon) {

        let input = document.getElementById(fieldId);
        let iconTag = icon.querySelector("i");

        if (input.type === "password") {

            input.type = "text";
            iconTag.classList.remove("bi-eye");
            iconTag.classList.add("bi-eye-slash");

        } else {

            input.type = "password";
            iconTag.classList.remove("bi-eye-slash");
            iconTag.classList.add("bi-eye");

        }

    }
    </script>

</body>

</html>