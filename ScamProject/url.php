<?php
session_start();
require_once '../Database/database.php';
require_once 'functions/translate.php';

// Handle language switch
if (isset($_GET['lang']) && in_array($_GET['lang'], ['en','vi'])) {
    $_SESSION['lang'] = $_GET['lang'];
    $currentPage = strtok($_SERVER["REQUEST_URI"], '?');
    header("Location: $currentPage");
    exit;
}
$lang = $_SESSION['lang'] ?? 'en';

/* =========================
GEMINI API KEY
========================= */
$dotenv_path = __DIR__ . '/.env';
$GEMINI_API_KEY = '';
if (file_exists($dotenv_path)) {
    $lines = file($dotenv_path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    foreach ($lines as $line) {
        if (strpos($line, 'GEMINI_API_KEY=') === 0) {
            $GEMINI_API_KEY = trim(substr($line, strlen('GEMINI_API_KEY=')));
        }
    }
}

/* =========================
ACTIVITY LOG FUNCTION
========================= */
function addLog($conn, $action, $target) {
    $user_id = $_SESSION['user_id'] ?? NULL;
    $username = $_SESSION['user_name'] ?? "Guest";
    $role = $_SESSION['role'] ?? "Guest";
    $ip = $_SERVER['REMOTE_ADDR'];
    $browser = $_SERVER['HTTP_USER_AGENT'];
    $stmt = $conn->prepare("
        INSERT INTO activity_logs
        (user_id, username, role, action, target, ip_address, user_agent)
        VALUES (?,?,?,?,?,?,?)
    ");
    $stmt->bind_param("issssss", $user_id, $username, $role, $action, $target, $ip, $browser);
    $stmt->execute();
}

/* =========================
GEMINI URL ANALYSIS
========================= */
function analyse_url_with_gemini(string $url, string $api_key): array {
    if (!$api_key) {
        return [
            'risk_level' => 'unknown',
            'reasons'    => ['Gemini API key not configured.'],
            'advice'     => 'AI analysis is unavailable. Use the quick scan result above as guidance.'
        ];
    }

    $endpoint = 'https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent';
    $prompt = "You are a cybersecurity expert specialising in URL and phishing analysis.\n"
            . "Analyse the following URL for signs of phishing, scam, or malicious intent.\n"
            . "Consider: domain reputation, suspicious patterns (lookalike domains, excessive subdomains, "
            . "IP addresses instead of domains, URL shorteners, suspicious TLDs, misspellings of known brands, "
            . "unusual ports, encoded characters, scam keywords, etc.).\n"
            . "Respond ONLY with a valid JSON object, no extra text, with this structure:\n"
            . "{\n"
            . "  \"risk_level\": \"low\" | \"medium\" | \"high\",\n"
            . "  \"reasons\": [\"short bullet reason 1\", \"short bullet reason 2\", ...],\n"
            . "  \"advice\": \"one short sentence of advice for the user\"\n"
            . "}\n"
            . "URL to analyse: {$url}";

    $payload = [
        'contents' => [['parts' => [['text' => $prompt]]]],
        'generationConfig' => ['response_mime_type' => 'application/json'],
    ];

    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL            => $endpoint . '?key=' . urlencode($api_key),
        CURLOPT_POST           => true,
        CURLOPT_HTTPHEADER     => ['Content-Type: application/json'],
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POSTFIELDS     => json_encode($payload),
        CURLOPT_TIMEOUT        => 20,
    ]);

    $rawResponse = curl_exec($ch);
    if ($rawResponse === false) {
        curl_close($ch);
        return ['risk_level' => 'unknown', 'reasons' => ['Failed to contact AI service.'], 'advice' => 'Try again later.'];
    }
    curl_close($ch);

    $data = json_decode($rawResponse, true);
    if (isset($data['error'])) {
        $msg = $data['error']['message'] ?? 'Unknown Gemini API error.';
        return ['risk_level' => 'unknown', 'reasons' => ["AI error: {$msg}"], 'advice' => 'AI analysis unavailable. Be careful.'];
    }

    $text = $data['candidates'][0]['content']['parts'][0]['text'] ?? '';
    $parsed = json_decode($text, true);
    if (!is_array($parsed) || !isset($parsed['risk_level'])) {
        if (preg_match('/\{.*\}/s', $text, $m)) {
            $parsed = json_decode($m[0], true);
        }
    }
    if (is_array($parsed) && isset($parsed['risk_level'])) {
        return [
            'risk_level' => $parsed['risk_level'] ?? 'unknown',
            'reasons'    => $parsed['reasons'] ?? [],
            'advice'     => $parsed['advice'] ?? '',
        ];
    }

    $lc = strtolower($text);
    $risk = str_contains($lc,'high') ? 'high' : (str_contains($lc,'medium') ? 'medium' : (str_contains($lc,'low') ? 'low' : 'unknown'));
    return ['risk_level' => $risk, 'reasons' => [$text ?: 'AI returned an unexpected response.'], 'advice' => 'Be careful before opening this URL.'];
}

/* =========================
GAMBLING POST-PROCESSING
========================= */
/**
 * Adjust AI analysis for gambling URLs/ads.
 * - Gambling site itself: at least medium risk.
 * - Site that advertises gambling: at least medium risk.
 * - Always add a reason entry explaining the gambling context.
 */
function apply_gambling_rules(string $url, array $analysis): array {
    global $lang;

    $lowerUrl   = strtolower($url);
    $lowerText  = strtolower(implode(" ", $analysis['reasons'] ?? []) . " " . ($analysis['advice'] ?? ''));

    $keywords = ['casino','bet','betting','sportsbook','slot','jackpot','poker','baccarat','roulette','bookmaker','wager','lotto','lottery','gamble','gambling'];
    $isGamblingUrl = false;

    foreach ($keywords as $kw) {
        if (str_contains($lowerUrl, $kw)) {
            $isGamblingUrl = true;
            break;
        }
    }

    $mentionedGambling = false;
    foreach ($keywords as $kw) {
        if (str_contains($lowerText, $kw)) {
            $mentionedGambling = true;
            break;
        }
    }

    if (!$isGamblingUrl && !$mentionedGambling) {
        return $analysis; // nothing to change
    }

    $risk = strtolower($analysis['risk_level'] ?? 'unknown');

    // Localised reason/advice templates
    if ($lang === 'vi') {
        $siteReason   = "Trang web này có vẻ là trang cờ bạc/cá cược trực tuyến, tiềm ẩn rủi ro tài chính và gây nghiện.";
        $adReason     = "Trang web này có vẻ đang quảng cáo hoặc giới thiệu dịch vụ cờ bạc/cá cược trực tuyến.";
        $defaultAdvice = "Hãy cẩn trọng với các trang liên quan đến cờ bạc, tránh nhấp vào liên kết và không cung cấp thông tin tài chính.";
    } else {
        $siteReason   = "This site appears to be a gambling or betting website, which carries financial and addiction risks.";
        $adReason     = "This site appears to promote or advertise online gambling services.";
        $defaultAdvice = "Be cautious with gambling-related sites; they can cause financial loss and may not be regulated.";
    }

    if ($isGamblingUrl) {
        // The URL itself looks like a gambling site
        if ($risk === 'low' || $risk === 'unknown') {
            $risk = 'medium';
        }
        $reasonText = $siteReason;
    } else {
        // Site that advertises/promotes gambling
        if ($risk === 'low' || $risk === 'unknown') {
            $risk = 'medium';
        }
        $reasonText = $adReason;
    }

    $analysis['risk_level'] = $risk;
    if (!isset($analysis['reasons']) || !is_array($analysis['reasons'])) {
        $analysis['reasons'] = [];
    }
    if (!in_array($reasonText, $analysis['reasons'], true)) {
        $analysis['reasons'][] = $reasonText;
    }

    if (empty($analysis['advice'])) {
        $analysis['advice'] = $defaultAdvice;
    }

    return $analysis;
}

/* =========================
HANDLE FORM SUBMISSION
========================= */
$ai_analysis = null;
$scanned_url  = '';
$error        = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $scanned_url = trim($_POST['url'] ?? '');

    if (empty($scanned_url)) {
        $error = "Please enter a URL.";
    } elseif (!filter_var($scanned_url, FILTER_VALIDATE_URL)) {
        $error = "Please enter a valid URL (e.g. https://example.com).";
    } else {
        addLog($conn, "URL Scan", $scanned_url);

        if (isset($_SESSION['user_id'])) {
            $user_id = $_SESSION['user_id'];
            $stmt = $conn->prepare("INSERT INTO search_history (user_id, phonenumber, result_type, scan_type) VALUES (?, ?, 'Pending', 'URL')");
            $stmt->bind_param("is", $user_id, $scanned_url);
            $stmt->execute();
            $history_id = $conn->insert_id;
        }

        $ai_analysis = analyse_url_with_gemini($scanned_url, $GEMINI_API_KEY);

        // Apply custom gambling rules (force at least medium, add reason)
        $ai_analysis = apply_gambling_rules($scanned_url, $ai_analysis);

        // Store risk_level directly as Low / Medium / High / Unknown
        $lvl = strtolower($ai_analysis['risk_level']);
        if ($lvl !== 'low' && $lvl !== 'medium' && $lvl !== 'high') {
            $lvl = 'unknown';
        }
        $result_type = ucfirst($lvl); // "Low", "Medium", "High", "Unknown"

        if (isset($history_id) && $history_id) {
            $stmtUp = $conn->prepare("UPDATE search_history SET result_type=? WHERE id=?");
            if ($stmtUp) {
                $stmtUp->bind_param("si", $result_type, $history_id);
                $stmtUp->execute();
                $stmtUp->close();
            }
        }
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
    <title><?php echo t("Scam Detection Platform"); ?></title>
    <style>
    body {
        background-image: url("img/background.png");
        background-size: cover;
        background-position: center;
        background-attachment: fixed;
    }
    .overlay {
        background: rgba(0,0,0,0.55);
        padding: 40px 0 60px;
        color: white;
        flex: 1;
        width: 100%;
    }
    .navbar { background: rgba(0,0,0,0.5); backdrop-filter: blur(6px); }
    .scan-card { background: rgba(0,0,0,0.6); border-radius: 12px; padding: 30px; color: white; }

    /* Quick scan */
    .meter { height: 14px; background: #1e293b; border-radius: 10px; overflow: hidden; margin-top: 12px; }
    .bar   { height: 100%; width: 0%; transition: width 1s ease; border-radius: 10px; }
    .quick-panel {
        margin-top: 12px; padding: 13px 16px; border-radius: 10px;
        background: rgba(0,0,0,0.45); border-left: 5px solid #6c757d;
        line-height: 1.75; font-size: 0.9rem;
    }
    .quick-panel.low    { border-color: #22c55e; }
    .quick-panel.medium { border-color: orange; }
    .quick-panel.high   { border-color: #ef4444; }
    .example-box {
        margin-top: 18px; padding: 16px; border-radius: 10px;
        background: rgba(0,0,0,0.4); border: 1px solid rgba(255,255,255,0.07);
        font-size: 0.85rem; line-height: 1.8; color: #cbd5e1;
    }
    .example-good { color: #22c55e; font-weight: bold; }
    .example-bad  { color: #ef4444; font-weight: bold; }

    /* AI result card */
      .result-card {
        background: #ffffff;
        border-radius: 12px;
        padding: 25px;
        margin-top: 22px;
        border: 5px solid transparent;
        color: #000;
}
    .border-high    { border-color: #dc3545; box-shadow: 0 0 20px rgba(220,53,69,0.4); }
    .border-medium  { border-color: #fd7e14; box-shadow: 0 0 20px rgba(253,126,20,0.4); }
    .border-low     { border-color: #28a745; box-shadow: 0 0 20px rgba(40,167,69,0.4); }
    .border-unknown { border-color: #6c757d; box-shadow: 0 0 20px rgba(108,117,125,0.4); }
    .risk-banner { color: white; font-size: 21px; font-weight: bold; text-align: center; padding: 14px; border-radius: 8px; margin-bottom: 18px; }
    .risk-high    { background: #dc3545; }
    .risk-medium  { background: #fd7e14; }
    .risk-low     { background: #28a745; }
    .risk-unknown { background: #6c757d; }
    .ai-box { background: #f8f9fa; border-left: 5px solid #0d6efd; padding: 16px; border-radius: 8px; }
    .url-display { background: #f1f3f5; border-radius: 8px; padding: 11px 15px; font-family: monospace; word-break: break-all; font-size: 0.9rem; }

    .footer-custom { background: rgba(0,0,0,0.75); color: white; }
    .footer-link   { color: #ddd; text-decoration: none; }
    .footer-link:hover { color: white; text-decoration: underline; }

    /* language buttons (reuse) */
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

    @keyframes fadeInDown {
        from { opacity:0; transform:translate(-50%,-16px); }
        to   { opacity:1; transform:translate(-50%,0); }
    }
    #alertToast {
        display: none; position: fixed; top: 80px; left: 50%;
        transform: translateX(-50%); background: #dc3545; color: white;
        padding: 14px 28px; border-radius: 10px; font-weight: bold;
        box-shadow: 0 0 25px rgba(0,0,0,0.6); z-index: 9999;
        animation: fadeInDown 0.4s ease;
    }
    </style>
</head>
<body class="d-flex flex-column min-vh-100">

    <div id="alertToast">🚨 High Risk URL Detected – Do NOT proceed!</div>

    <!-- NAVBAR -->
    <nav class="navbar navbar-expand-lg navbar-dark w-100 fixed-top shadow-sm">
        <div class="container-fluid">
            <a class="navbar-brand fw-bold fs-3 me-5" href="index.php"><?php echo t("SCAM PROOF"); ?></a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav me-auto mb-2 mb-lg-0 mx-4 gap-5 fs-6">
                    <li class="nav-item"><a class="nav-link" href="index.php"><?php echo t("HOME");?></a></li>
                    <li class="nav-item"><a class="nav-link" href="phonenumber.php"><?php echo t("PHONE NUMBER");?></a></li>
                    <li class="nav-item"><a class="nav-link active" href="url.php"><?php echo t("URL");?></a></li>
                    <li class="nav-item"><a class="nav-link" href="email.php"><?php echo t("EMAIL");?></a></li>
                </ul>
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
                        <a class="d-flex align-items-center text-white text-decoration-none dropdown-toggle"
                           href="#" role="button" data-bs-toggle="dropdown" aria-expanded="false">
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

    <!-- CONTENT -->
    <div class="overlay">
        <div class="container mt-5 pt-5">
            <h2 class="text-center mb-4 mt-4"><?php echo t("URL Scan"); ?></h2>

           <?php if ($error): ?>
            <div class="alert alert-danger text-center"><?php echo htmlspecialchars(t($error)); ?></div>
            <?php endif; ?>

            <div class="row justify-content-center">
                <div class="col-md-9 col-lg-7">
                    <div class="scan-card">

                        <!-- AI URL SCAN ONLY -->
                        <h6 class="text-uppercase fw-bold mb-2" style="color:#94a3b8; letter-spacing:.05em;">
                            <i class="bi bi-robot me-1" style="color:#60a5fa;"></i>
                            <?php echo t("URL Scan"); ?>
                            <span class="badge ms-2" style="background:#1e3a5f; font-size:.68rem;">~5 sec</span>
                        </h6>
                        <form method="POST" id="aiForm">
                            <div class="input-group mb-1">
                                <input type="url" name="url" id="aiUrlInput"
                                       class="form-control bg-dark text-white border-secondary"
                                       placeholder="https://example.com" required
                                       value="<?php echo htmlspecialchars($scanned_url); ?>">
                                <button type="submit" class="btn btn-primary fw-bold" id="scanBtn">
                                    <span class="spinner-border spinner-border-sm visually-hidden" id="loadingSpinner"></span>
                                    <span id="btnText"><i class="bi bi-robot me-1"></i>Scan URL</span>
                                    <span class="visually-hidden" id="loadingText">Scanning…</span>
                                </button>
                            </div>
                        </form>

                        <!-- AI RESULT -->
                        <?php if ($ai_analysis): ?>
                        <?php
                            $lvl = strtolower($ai_analysis['risk_level']);
                            $borderClass = "border-$lvl";
                            $bannerClass = "risk-$lvl";
                            $riskLabel   = strtoupper($ai_analysis['risk_level']);
                            $riskIcon    = $lvl === 'high'   ? 'bi-exclamation-triangle-fill' :
                                          ($lvl === 'medium' ? 'bi-exclamation-circle-fill'   :
                                          ($lvl === 'low'    ? 'bi-shield-check-fill'          : 'bi-question-circle-fill'));
                        ?>
                        <div class="result-card <?php echo $borderClass; ?>">
                            <div class="risk-banner <?php echo $bannerClass; ?>">
                                <i class="bi <?php echo $riskIcon; ?> me-2"></i>
                            <?php echo t("Risk Level:"); ?> <?php echo $riskLabel; ?>
                            </div>

                            <h6><i class="bi bi-link-45deg me-1"></i><?php echo t("Scanned URL");?></h6>
                            <div class="url-display mb-3"><?php echo htmlspecialchars($scanned_url); ?></div>

                            <?php if (!empty($ai_analysis['reasons'])): ?>
                            <div class="ai-box mb-3">
                                <h6><i class="bi bi-robot me-2"></i><?php echo t("AI Detection Reasons");?></h6>
                                <ul class="mb-0">
                                    <?php foreach ($ai_analysis['reasons'] as $r): ?>
                                    <li><?php echo htmlspecialchars($r); ?></li>
                                    <?php endforeach; ?>
                                </ul>
                            </div>
                            <?php endif; ?>

                            <?php if (!empty($ai_analysis['advice'])): ?>
                            <div class="alert alert-info mb-2">
                                <i class="bi bi-lightbulb me-2"></i>
                                <strong><?php echo t("Advice:");?></strong> <?php echo htmlspecialchars($ai_analysis['advice']); ?>
                            </div>
                            <?php endif; ?>

                            <div class="alert alert-warning mb-3">
                                <i class="bi bi-shield-exclamation me-2"></i>
                                <?php echo t("Never enter passwords or personal data on suspicious sites.");?>
                            </div>

                            <div class="mb-2">
                                <small class="text-muted">
                                    This information is provided for reference purposes only and should not be considered absolute.
                                    We do not guarantee the accuracy of the results and are not responsible for decisions made based on this information.
                                </small>
                            </div>

                            <div class="text-center">
                                <a href="url.php" class="btn btn-secondary me-2">
                                    <i class="bi bi-arrow-left me-1"></i><?php echo t("Scan Another");?>
                                </a>
                                <a href="index.php" class="btn btn-outline-secondary">
                                    <i class="bi bi-house me-1"></i><?php echo t("HOME");?>
                                </a>
                            </div>
                        </div>
                        <?php endif; ?>

                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- FOOTER -->
    <footer class="py-3 border-top footer-custom mt-auto">
        <div class="container">
            <div class="d-flex justify-content-between align-items-center small">
                <div><?php echo t("© 2026 Scam Detection Platform – BTEC FPT"); ?></div>
                <div>
                    <a href="#" class="footer-link"><?php echo t("Privacy Policy");?></a>
                    &middot;
                    <a href="#" class="footer-link"><?php echo t("Terms & Conditions");?></a>
                </div>
            </div>
        </div>
    </footer>

<script>
/* =====================================================
   AI FORM — loading spinner
   ===================================================== */
const aiForm      = document.getElementById('aiForm');
const scanBtn     = document.getElementById('scanBtn');
const spinner     = document.getElementById('loadingSpinner');
const btnText     = document.getElementById('btnText');
const loadingText = document.getElementById('loadingText');

function resetBtn() {
    if (!spinner || !loadingText || !btnText || !scanBtn) return;
    spinner.classList.add('visually-hidden');
    loadingText.classList.add('visually-hidden');
    btnText.classList.remove('visually-hidden');
    scanBtn.disabled = false;
}
resetBtn();
window.addEventListener('pageshow', resetBtn);

if (aiForm) {
    aiForm.addEventListener('submit', function () {
        if (!aiForm.checkValidity()) return;
        spinner.classList.remove('visually-hidden');
        loadingText.classList.remove('visually-hidden');
        btnText.classList.add('visually-hidden');
        scanBtn.disabled = true;
    });
}

// Sync both inputs while typing
document.getElementById('quickUrlInput').addEventListener('input', function () {
    document.getElementById('aiUrlInput').value = this.value;
});
document.getElementById('aiUrlInput').addEventListener('input', function () {
    document.getElementById('quickUrlInput').value = this.value;
});
</script>
</body>
</html>