<?php
session_start();
require_once '../Database/database.php';

/* =========================
ACTIVITY LOG FUNCTION
========================= */

function addLog($conn,$action,$target){

$user_id = $_SESSION['user_id'] ?? NULL;
$username = $_SESSION['user_name'] ?? "Guest";
$role = $_SESSION['role'] ?? "Guest";

$ip = $_SERVER['REMOTE_ADDR'];
$browser = $_SERVER['HTTP_USER_AGENT'];

$stmt = $conn->prepare("
INSERT INTO activity_logs
(user_id,username,role,action,target,ip_address,user_agent)
VALUES (?,?,?,?,?,?,?)
");

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

}

$error = "";

if ($_SERVER["REQUEST_METHOD"] == "POST") {

    $phone = trim($_POST['phone']);

    if (!preg_match('/^0[0-9]{9}$/', $phone)) {
        $error = "Phone number must start with 0 and contain exactly 10 digits.";
    } else {
        addLog($conn,"Search Phone",$phone);

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

    <title>Check Phone Number</title>

    <style>
    body {
        background-image: url("img/background.png");
        background-size: cover;
        background-position: center;
        background-attachment: fixed;
    }

    .overlay {
        background: rgba(0, 0, 0, 0.55);
        padding: 40px 0;
        color: white;
        flex: 1;
        width: 100%;
    }

    .navbar {
        background: rgba(0, 0, 0, 0.5);
        backdrop-filter: blur(6px);
    }

    .footer-custom {
        background: rgba(0, 0, 0, 0.75);
        color: white;
    }

    .footer-link {
        color: #ddd;
        text-decoration: none;
    }

    .footer-link:hover {
        color: white;
        text-decoration: underline;
    }
    </style>

</head>

<body class="d-flex flex-column min-vh-100">


    <!-- NAVBAR -->

    <nav class="navbar navbar-expand-lg navbar-dark w-100 fixed-top shadow-sm">

        <div class="container-fluid">

            <a class="navbar-brand fw-bold fs-3 me-5" href="index.php">
                SCAM BTEC
            </a>

            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>

            <div class="collapse navbar-collapse" id="navbarNav">

                <ul class="navbar-nav me-auto mb-2 mb-lg-0 mx-4 gap-5 fs-6">

                    <li class="nav-item">
                        <a class="nav-link active" href="index.php">HOME</a>
                    </li>

                    <li class="nav-item">
                        <a class="nav-link active" href="phonenumber.php">PHONE NUMBER</a>
                    </li>

                    <li class="nav-item">
                        <a class="nav-link active" href="#">URL</a>
                    </li>

                    <li class="nav-item">
                        <a class="nav-link active" href="#">EMAIL</a>
                    </li>

                </ul>

                <div class="d-flex align-items-center gap-3">

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
                                    History
                                </a>
                            </li>

                            <li>
                                <hr class="dropdown-divider">
                            </li>

                            <li>
                                <a class="dropdown-item text-danger" href="logout.php">
                                    <i class="bi bi-box-arrow-right me-2"></i>
                                    Logout
                                </a>
                            </li>

                        </ul>

                    </div>

                    <?php else: ?>

                    <a href="login.php" class="btn btn-outline-info">Sign in</a>
                    <a href="register.php" class="btn btn-outline-info">Sign up</a>

                    <?php endif; ?>

                </div>

            </div>

        </div>

    </nav>

    <!-- MAIN CONTENT -->

    <div class="overlay">
        <div class="container mt-5 pt-5 flex-grow-1">
            <h2 class="text-center mb-4 mt-5">
                CHECK PHONE NUMBER
            </h2>

            <form method="POST" onsubmit="return validateForm()">

                <div class="row justify-content-center">

                    <div class="col-md-6">

                        <input type="text" id="phoneInput" name="phone" class="form-control mb-2"
                            placeholder="Enter phone number..." oninput="validatePhone()" required>

                        <small id="errorText" class="text-danger d-none">
                            Phone number must start with 0 and contain exactly 10 digits.
                        </small>

                        <button type="submit" class="btn btn-primary w-100 mt-3">
                            Check
                        </button>

                    </div>

                </div>

            </form>

            <?php if($error!=""){ ?> 
            <div class="alert alert-danger text-center mt-3"> 
                <?php echo $error; ?> 
            </div>
            <?php } ?>

        </div>

    </div>

    <!-- FOOTER -->

    <footer class="py-3 border-top footer-custom mt-auto">

        <div class="container">

            <div class="d-flex justify-content-between align-items-center small">

                <div>
                    © 2026 Scam Detection Platform – BTEC FPT
                </div>

                <div>
                    <a href="#" class="footer-link">Privacy Policy</a>
                    &middot;
                    <a href="#" class="footer-link">Terms & Conditions</a>
                </div>

            </div>

        </div>

    </footer>

</body>

</html>

<script>
function validatePhone() {

    const phoneInput = document.getElementById("phoneInput");
    const errorText = document.getElementById("errorText");

    const phone = phoneInput.value;

    const phoneRegex = /^0[0-9]{9}$/;

    if (!phoneRegex.test(phone)) {

        errorText.classList.remove("d-none");
        phoneInput.classList.add("is-invalid");
        phoneInput.classList.remove("is-valid");

        return false;

    } else {

        errorText.classList.add("d-none");
        phoneInput.classList.remove("is-invalid");
        phoneInput.classList.add("is-valid");

        return true;
    }

}

function validateForm() {
    return validatePhone();
}
</script>