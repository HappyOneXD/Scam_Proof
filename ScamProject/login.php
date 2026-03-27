<?php
session_start();
require_once '../Database/database.php';
require_once 'functions/translate.php';

// Language switch
if (isset($_GET['lang']) && in_array($_GET['lang'], ['en','vi'])) {
    $_SESSION['lang'] = $_GET['lang'];
    $currentPage = strtok($_SERVER["REQUEST_URI"], '?');
    header("Location: $currentPage");
    exit;
}
$lang = $_SESSION['lang'] ?? 'en';

/* CHECK IF USER ALREADY LOGIN */
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

if($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST["username"]) && isset($_POST["password"])) {

    $username = trim($_POST["username"]);
    $password = $_POST["password"];

    $ip = $_SERVER['REMOTE_ADDR'];
    $browser = $_SERVER['HTTP_USER_AGENT'];

    try {
        $sql_query = "SELECT * FROM users WHERE username = ? LIMIT 1";
        $stmt = $conn->prepare($sql_query);
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows > 0) {

            $user = $result->fetch_assoc();

            if (password_verify($password, $user['password'])) {

                $user_id = $user['id'];
                $user_name = $user['username'];
                $role = $user['role'];

                $_SESSION['user_id'] = $user_id;
                $_SESSION['user_name'] = $user_name;
                $_SESSION['role'] = $role;

                $stmt = $conn->prepare("UPDATE users SET status='Active', last_login=NOW() WHERE id=?");
                $stmt->bind_param("i",$user_id);
                $stmt->execute();

                // ACTIVITY LOG
                $stmt = $conn->prepare("
                    INSERT INTO activity_logs
                    (user_id,username,role,action,target,ip_address,user_agent)
                    VALUES (?,?,?,?,?,?,?)
                ");
                $action = t("Login Success");
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

                if($role == "Admin"){
                    header("Location: admin/admin_dashboard.php");
                    exit;
                }else{
                    header("Location: index.php");
                    exit;
                }

            } else {
                $error = t("Wrong password.");
            }

        } else {
            $error = t("Username or password is incorrect.");
        }

    } catch (Exception $e) {
        echo t("Login error: ") . " ". $e->getMessage();
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

    <title><?php echo t("Login");?></title>
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

    .lang-btn {
        display: flex;
        align-items: center;
        padding: 4px 10px;
        border-radius: 6px;
        font-size: 0.85rem;
        font-weight: 600;
        text-decoration: none;
        transition: all 0.3s ease;
        background: #f8f9fa;
        color: #334155;
        border: 1px solid #e2e8f0;
    }

    .lang-btn.active {
        background: #0ea5e9;
        color: white;
        border-color: #0ea5e9;
        box-shadow: 0 0 10px rgba(14, 165, 233, 0.4);
    }

    .flag-img {
        width: 20px;
        height: 15px;
        object-fit: cover;
        border-radius: 2px;
        box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
    }

    .lang-btn:hover:not(.active) {
        background: #e2e8f0;
        transform: translateY(-1px);
    }
    </style>

</head>

<body>

    <div class="overlay">

        <?php $lang = $_SESSION['lang'] ?? 'en'; ?>
        <div class="lang-switch position-absolute top-0 end-0 m-3 d-flex gap-2">
            <a href="?lang=en" class="lang-btn <?php echo $lang=='en' ? 'active' : ''; ?>">
                <img src="https://flagcdn.com/w40/gb.png" class="flag-img" alt="English">
                EN
            </a>
            <a href="?lang=vi" class="lang-btn <?php echo $lang=='vi' ? 'active' : ''; ?>">
                <img src="https://flagcdn.com/w40/vn.png" class="flag-img" alt="Vietnamese">
                VI
            </a>
        </div>

        <div class="login-box">

            <h3 class="text-center mb-4"><?php echo t("Login");?></h3>

            <?php if(!empty($error)){ ?>
            <div class="alert alert-danger text-center">
                <?php echo $error ?>
            </div>
            <?php } ?>

            <form method="POST">

                <div class="mb-3">
                    <label class="form-label"><?php echo t("Username");?></label>
                    <input type="text" class="form-control" name="username" required>
                </div>

                <div class="mb-3">
                    <label class="form-label"><?php echo t("Password");?></label>
                    <div class="input-group">
                        <input type="password" class="form-control" id="password" name="password" required>
                        <span class="input-group-text" onclick="togglePassword('password',this)">
                            <i class="bi bi-eye"></i>
                        </span>
                    </div>
                </div>

                <div class="d-flex justify-content-between mt-3">
                    <button type="submit" class="btn btn-primary">
                        <?php echo t("Login");?>
                    </button>
                    <a href="index.php" class="btn btn-secondary">
                        <?php echo t("← Back");?>
                    </a>
                </div>

            </form>

            <div class="links">
                <a href="register.php"><?php echo t("Don't have an account? Register here");?></a>
                <a href="forgot_password.php"><?php echo t("Forgot Password?");?></a>
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
