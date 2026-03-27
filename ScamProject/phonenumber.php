<?php
session_start();
require_once '../Database/database.php';
require_once 'functions/translate.php';

// Xử lý thay đổi ngôn ngữ
if (isset($_GET['lang']) && in_array($_GET['lang'], ['en','vi'])) {
    $_SESSION['lang'] = $_GET['lang'];
    $currentPage = strtok($_SERVER["REQUEST_URI"], '?');
    header("Location: $currentPage");
    exit;
}
$lang = $_SESSION['lang'] ?? 'en';

/* =========================
ACTIVITY LOG FUNCTION
========================= */
function addLog($conn,$action,$target){
    $user_id  = $_SESSION['user_id']  ?? NULL;
    $username = $_SESSION['user_name'] ?? "Guest";
    $role     = $_SESSION['role']      ?? "Guest";

    $allowed_roles = ["Admin","User","Employee","Guest"];
    if(!in_array($role,$allowed_roles)){
        $role = "User";
    }

    if(!empty($_SERVER['HTTP_X_FORWARDED_FOR'])){
        $ip = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'])[0];
    }else{
        $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    }
    $browser = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';

    $stmt = $conn->prepare("
        INSERT INTO activity_logs
        (user_id,username,role,action,target,ip_address,user_agent)
        VALUES (?,?,?,?,?,?,?)
    ");

    if($stmt){
        $stmt->bind_param(
            "issssss",
            $user_id,
            $username,
            $role,
            $action,
            $target,
            $ip,
            $browser
        );
        $stmt->execute();
        $stmt->close();
    }
}

$error = "";
$serviceWarning = "";

/* =========================
HANDLE FORM SUBMISSION
========================= */
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $phone = trim($_POST['phone']);

    // 0xxxxxxxx (8–11 digits) OR 1900xxxx
    if (!preg_match('/^(0\d{7,10}|1900\d{4})$/', $phone)) {
        $error = t("Phone number must be a valid Vietnamese number (0xxxxxxxx or 1900xxxx).");
    } else {

        // Premium 1900 service notice
        if (preg_match('/^1900\d{4}$/', $phone)) {
            $serviceWarning = t("This is a premium service number (1900).");
        }

        addLog($conn, "Search Phone", $phone);

        // Store in search_history as Phone
        if (isset($_SESSION['user_id'])) {
            $user_id = $_SESSION['user_id'];
            $stmt = $conn->prepare("
                INSERT INTO search_history (user_id, phonenumber, result_type, scan_type)
                VALUES (?, ?, 'Unknown', 'Phone')
            ");
            if ($stmt) {
                $stmt->bind_param("is", $user_id, $phone);
                $stmt->execute();
                $stmt->close();
            }
        }

        header("Location: result.php?phone=" . urlencode($phone));
        exit();
    }
}
?>
<!DOCTYPE html>
<html lang="en">

<head>

    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons/font/bootstrap-icons.css">

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/js/bootstrap.bundle.min.js"></script>

    <title><?php echo t("Check Phone Number");?></title>

    <style>
    html, body {
        height: 100%;
        margin: 0;
        padding: 0;
    }

    body {
        display: flex;
        flex-direction: column;
        min-height: 100vh;
        background-image: url("img/background.png");
        background-size: cover;
        background-position: center;
        color: white;
    }

    .overlay {
        flex-grow: 1;
        display: flex;
        justify-content: center;
        align-items: center;
        padding-top: 80px;
        padding-bottom: 40px;
        background: rgba(0, 0, 0, 0.55);
    }

    .navbar {
        background: rgba(0, 0, 0, 0.5);
        backdrop-filter: blur(6px);
        z-index: 10500;
    }

    .footer-custom {
        background: rgba(0, 0, 0, 0.75);
        color: white;
        padding: 15px 0;
    }

    .footer-link {
        color: #ddd;
        text-decoration: none;
    }

    .footer-link:hover {
        color: white;
        text-decoration: underline;
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

<body class="d-flex flex-column min-vh-100">

    <!-- NAVBAR -->
    <nav class="navbar navbar-expand-lg navbar-dark w-100 fixed-top shadow-sm">
        <div class="container-fluid">

            <a class="navbar-brand fw-bold fs-3 me-5" href="index.php">
                <?php echo t("SCAM PROOF"); ?>
            </a>

            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>

            <div class="collapse navbar-collapse" id="navbarNav">

                <!-- Left menu -->
                <ul class="navbar-nav me-auto mb-2 mb-lg-0 mx-4 gap-5 fs-6">

                    <li class="nav-item">
                        <a class="nav-link active" href="index.php"><?php echo t("HOME");?></a>
                    </li>

                    <li class="nav-item">
                        <a class="nav-link active" href="phonenumber.php"><?php echo t("PHONE NUMBER");?></a>
                    </li>

                    <li class="nav-item">
                        <a class="nav-link" href="url.php"><?php echo t("URL");?></a>
                    </li>

                    <li class="nav-item">
                        <a class="nav-link" href="email.php"><?php echo t("EMAIL");?></a>
                    </li>

                </ul>

                <!-- Right (language + user) -->
                <div class="d-flex align-items-center gap-3">

                    <?php $lang = $_SESSION['lang'] ?? 'en'; ?>
                    <div class="d-flex gap-2 ms-3 align-items-center">

                        <a href="?lang=en" class="lang-btn <?php echo $lang=='en' ? 'active' : ''; ?>">
                            <img src="https://flagcdn.com/w40/gb.png" class="flag-img" alt="English">
                            <span class="ms-1">EN</span>
                        </a>

                        <a href="?lang=vi" class="lang-btn <?php echo $lang=='vi' ? 'active' : ''; ?>">
                            <img src="https://flagcdn.com/w40/vn.png" class="flag-img" alt="Vietnamese">
                            <span class="ms-1">VI</span>
                        </a>

                    </div>

                    <?php if (isset($_SESSION['user_id'])): ?>

                    <div class="dropdown">

                        <a class="d-flex align-items-center text-white text-decoration-none dropdown-toggle" href="#"
                           data-bs-toggle="dropdown">

                            <i class="bi bi-person-circle fs-3"></i>

                        </a>

                        <ul class="dropdown-menu dropdown-menu-end shadow">

                            <li class="dropdown-header">
                                <a href="profile.php" class="text-decoration-none text-dark">
                                    <?php echo htmlspecialchars($_SESSION['user_name']); ?>
                                </a>
                            </li>

                            <li>
                                <a class="dropdown-item" href="history.php">
                                    <i class="bi bi-clock-history me-2"></i>
                                    <?php echo t("History"); ?>
                                </a>
                            </li>

                            <li><hr class="dropdown-divider"></li>

                            <li>
                                <a class="dropdown-item text-danger" href="logout.php">
                                    <i class="bi bi-box-arrow-right me-2"></i>
                                    <?php echo t("Logout"); ?>
                                </a>
                            </li>

                        </ul>

                    </div>

                    <?php else: ?>

                    <a href="login.php" class="btn btn-outline-info"><?php echo t("Sign in"); ?></a>
                    <a href="register.php" class="btn btn-outline-info"><?php echo t("Sign up"); ?></a>

                    <?php endif; ?>

                </div>

            </div>

        </div>

    </nav>

    <!-- MAIN CONTENT -->
    <div class="overlay">
        <div class="container">

            <div class="row justify-content-center">

                <div class="col-md-6 col-lg-5">

                    <h2 class="text-center mb-4">
                        <?php echo t("CHECK PHONE NUMBER");?>
                    </h2>

                    <form method="POST" onsubmit="return validateForm()">

                        <input
                            type="text"
                            id="phoneInput"
                            name="phone"
                            class="form-control mb-2"
                            placeholder="<?php echo t('Enter phone number...');?>"
                            oninput="validatePhone()"
                            required
                        >

                        <small id="errorText" class="text-danger d-none">
                            <?php echo t("Phone number must be a valid Vietnamese number (0xxxxxxxx or 1900xxxx).");?>
                        </small>

                        <small id="phoneInfo" class="text-warning d-none">
                            <?php echo t("This is a premium service number (1900).");?>
                        </small>

                        <button type="submit" class="btn btn-primary w-100 mt-3">
                            <?php echo t("Check Phone number");?>
                        </button>

                    </form>

                    <?php if($error!=""){ ?>
                    <div class="alert alert-danger text-center mt-3">
                        <?php echo htmlspecialchars($error); ?>
                    </div>
                    <?php } ?>

                    <?php if($serviceWarning!=""){ ?>
                    <div class="alert alert-warning text-center mt-3">
                        <?php echo htmlspecialchars($serviceWarning); ?>
                    </div>
                    <?php } ?>

                </div>

            </div>

        </div>
    </div>

    <!-- FOOTER -->
    <footer class="py-3 border-top footer-custom">
        <div class="container">
            <div class="d-flex justify-content-between align-items-center small">

                <div>
                    <?php echo t("© 2026 Scam Detection Platform – BTEC FPT"); ?>
                </div>

                <div>
                    <a href="#" class="footer-link"><?php echo t("Privacy Policy");?></a>
                    &middot;
                    <a href="#" class="footer-link"><?php echo t("Terms & Conditions");?></a>
                </div>

            </div>
        </div>
    </footer>

</body>

</html>

<script>
function validatePhone() {

    const phoneInput  = document.getElementById("phoneInput");
    const errorText   = document.getElementById("errorText");
    const phoneInfo   = document.getElementById("phoneInfo");

    const phone = phoneInput.value.trim();
    const phoneRegex = /^(0\d{7,10}|1900\d{4})$/;

    if (!phoneRegex.test(phone)) {

        errorText.classList.remove("d-none");
        phoneInput.classList.add("is-invalid");
        phoneInput.classList.remove("is-valid");
        phoneInfo.classList.add("d-none");

        return false;

    } else {

        errorText.classList.add("d-none");
        phoneInput.classList.remove("is-invalid");
        phoneInput.classList.add("is-valid");

        if (/^1900\d{4}$/.test(phone)) {
            phoneInfo.classList.remove("d-none");
        } else {
            phoneInfo.classList.add("d-none");
        }

        return true;
    }
}

function validateForm() {
    return validatePhone();
}
</script>
