<?php
session_start();
require_once '../Database/database.php';
?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons/font/bootstrap-icons.css">

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/js/bootstrap.bundle.min.js"></script>

    <title>Scam Detection Platform</title>

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

    .banner-box {
        border: 2px solid #000;
        padding: 40px;
        background: rgba(0, 0, 0, 0.7);
        color: white;
        min-height: 250px;
        margin-top: 80px;

        display: flex;
        align-items: center;
    }

    .banner-text {
        max-width: 500px;
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

    <!-- ================= NAVBAR ================= -->
    <nav class="navbar navbar-expand-lg navbar-dark w-100 fixed-top shadow-sm">
        <div class="container-fluid">

            <a class="navbar-brand fw-bold fs-3 me-5" href="index.php">SCAM BTEC</a>

            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>

            <div class="collapse navbar-collapse" id="navbarNav">

                <!-- Menu trái -->
                <ul class="navbar-nav me-auto mb-2 mb-lg-0 mx-4 gap-5 fs-6">
                    <li class="nav-item">
                        <a class="nav-link active" aria-current="page" href="index.php">HOME</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link active" aria-current="page" href="phonenumber.php">PHONE NUMBER</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link active" aria-current="page" href="#">URL</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link active" aria-current="page" href="#">EMAIL</a>
                    </li>
                </ul>

                <!-- Menu phải (User) -->
                <div class="d-flex align-items-center gap-3">

                    <?php if (isset($_SESSION['user_id'])): ?>

                    <!-- Dropdown User -->
                    <div class="dropdown">
                        <a class="d-flex align-items-center text-white text-decoration-none dropdown-toggle" href="#"
                            role="button" data-bs-toggle="dropdown" aria-expanded="false">

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

                    <a href="login.php" class="btn btn-outline-info">
                        Sign in
                    </a>

                    <a href="register.php" class="btn btn-outline-info">
                        Sign up
                    </a>

                    <?php endif; ?>

                </div>
            </div>
        </div>
    </nav>

    <!-- ================= MAIN CONTENT ================= -->

    <div class="overlay">
        <div class="container mt-5 pt-5 flex-grow-1">
            <h1 class="mt-5 text-center mb-2">Welcome to Scam Detection Platform</h1>
        </div>
        <div class="container mt-4">
            <div class="banner-box">
                <div class="banner-text">
                    <h3>Scam & Threat Detection</h3>
                    <p>
                        This platform helps users detect phishing websites,
                        suspicious emails and scam phone numbers.
                    </p>

                    <p>
                        Tips: Always check the URL carefully and avoid
                        entering personal information on unknown websites.
                    </p>
                </div>
            </div>
        </div>
    </div>

    <!-- ================= FOOTER ================= -->

    <footer class="py-3 border-top footer-custom">
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