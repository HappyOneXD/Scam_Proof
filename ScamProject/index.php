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
?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons/font/bootstrap-icons.css">
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/js/bootstrap.bundle.min.js"></script>

    <title><?php echo t("Scam Detection Platform"); ?></title>

    <style>
    html, body {
        height: 100%;
        margin: 0;
        padding: 0;
    }

    body {
        background-image: url("img/background.png");
        background-size: cover;
        background-position: center;
        background-attachment: fixed;
        padding-top: 10px;
    }

    .overlay {
        background: rgba(0, 0, 0, 0.55);
        padding: 40px 0;
        color: white;
        width: 100%;
        min-height: calc(100vh - 70px);
        display: flex;
        flex-direction: column;
        justify-content: center;
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

    /* language buttons */
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
        box-shadow: 0 1px 3px rgba(0,0,0,0.1);
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

            <a class="navbar-brand fw-bold fs-3 me-5" href="index.php"><?php echo t("SCAM PROOF"); ?></a>

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
                        <a class="nav-link" href="phonenumber.php"><?php echo t("PHONE NUMBER");?></a>
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

                    <a href="login.php" class="btn btn-outline-info">
                        <?php echo t("Sign in"); ?>
                    </a>
                    <a href="register.php" class="btn btn-outline-info">
                        <?php echo t("Sign up"); ?>
                    </a>

                    <?php endif; ?>

                </div>
            </div>
        </div>
    </nav>

    <!-- MAIN CONTENT -->
    <div class="overlay">
        <div class="container mt-5 pt-5 flex-grow-1">
            <h1 class="mt-5 text-center mb-2">
                <?php echo t("Welcome to Scam Detection Platform"); ?>
            </h1>
        </div>
        <div class="container mt-4">
            <div class="banner-box">
                <div class="banner-text">
                    <h3><?php echo t("Scam & Threat Detection"); ?></h3>
                    <p>
                        <?php echo t("This platform helps users detect phishing websites,
                        suspicious emails and scam phone numbers."); ?>
                    </p>

                    <p>
                        <?php echo t("Tips: Always check the URL carefully and avoid
                        entering personal information on unknown websites."); ?>
                    </p>
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
