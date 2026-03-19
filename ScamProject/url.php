<?php
session_start();
require_once '../Database/database.php';

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

    $endpoint = 'https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent';
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

        // SRS FR4.2: Low(0-33%) = Legitimate, Medium(34-66%) = Suspicious, High(67-100%) = Scam
        $lvl = strtolower($ai_analysis['risk_level']);
        $result_type = $lvl === 'high' ? 'Scam' : ($lvl === 'medium' ? 'Suspicious' : ($lvl === 'low' ? 'Legitimate' : 'Unknown'));
        if (isset($history_id) && $history_id) {
            $conn->query("UPDATE search_history SET result_type='$result_type' WHERE id=$history_id");
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
    <title>URL Scan – SCAM BTEC</title>
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
    .result-card { background: white; border-radius: 12px; padding: 25px; margin-top: 22px; border: 5px solid transparent; }
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
            <a class="navbar-brand fw-bold fs-3 me-5" href="index.php">SCAM BTEC</a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav me-auto mb-2 mb-lg-0 mx-4 gap-5 fs-6">
                    <li class="nav-item"><a class="nav-link" href="index.php">HOME</a></li>
                    <li class="nav-item"><a class="nav-link" href="phonenumber.php">PHONE NUMBER</a></li>
                    <li class="nav-item"><a class="nav-link active" href="url.php">URL</a></li>
                    <li class="nav-item"><a class="nav-link" href="email.php">EMAIL</a></li>
                </ul>
                <div class="d-flex align-items-center gap-3">
                    <?php if (isset($_SESSION['user_id'])): ?>
                    <div class="dropdown">
                        <a class="d-flex align-items-center text-white text-decoration-none dropdown-toggle"
                           href="#" role="button" data-bs-toggle="dropdown">
                            <i class="bi bi-person-circle fs-3"></i>
                        </a>
                        <ul class="dropdown-menu dropdown-menu-end shadow">
                            <li class="dropdown-header">
                                <a href="profile.php" class="text-decoration-none text-dark">
                                    <?php echo htmlspecialchars($_SESSION['user_name']); ?>
                                </a>
                            </li>
                            <li><a class="dropdown-item" href="history.php"><i class="bi bi-clock-history me-2"></i>History</a></li>
                            <li><hr class="dropdown-divider"></li>
                            <li><a class="dropdown-item text-danger" href="logout.php"><i class="bi bi-box-arrow-right me-2"></i>Logout</a></li>
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

    <!-- CONTENT -->
    <div class="overlay">
        <div class="container mt-5 pt-5">
            <h2 class="text-center mb-4 mt-4">URL SCAN</h2>

            <?php if ($error): ?>
            <div class="alert alert-danger text-center"><?php echo htmlspecialchars($error); ?></div>
            <?php endif; ?>

            <div class="row justify-content-center">
                <div class="col-md-9 col-lg-7">
                    <div class="scan-card">

                        <!-- QUICK SCAN -->
                        <h6 class="text-uppercase fw-bold mb-2" style="color:#94a3b8; letter-spacing:.05em;">
                            <i class="bi bi-lightning-charge-fill me-1" style="color:#22c55e;"></i>
                            Quick Scan
                            <span class="badge ms-2" style="background:#1e293b; font-size:.68rem;">Instant · No server</span>
                        </h6>
                        <div class="input-group mb-1">
                            <input type="url" id="quickUrlInput" class="form-control bg-dark text-white border-secondary"
                                   placeholder="https://example.com"
                                   value="<?php echo htmlspecialchars($scanned_url); ?>">
                            <button class="btn btn-success fw-bold" onclick="quickScan()">
                                <i class="bi bi-lightning-charge me-1"></i>Check
                            </button>
                        </div>
                        <small class="text-muted d-block mb-2">Instant rule-based check — results appear immediately</small>

                        <div class="meter"><div id="quickBar" class="bar"></div></div>
                        <div id="quickResult"></div>

                        <div id="exampleBox" class="example-box">
                            <div class="example-good mb-1">✅ Trusted examples</div>
                            https://google.com &nbsp;·&nbsp; https://facebook.com &nbsp;·&nbsp; https://bankname.com
                            <div class="example-bad mt-2 mb-1">🚨 Suspicious examples</div>
                            http://verify-bank-login-update.com<br>
                            http://free-gift-card-urgent.net &nbsp;·&nbsp; http://paypal-security-check123.com
                            <div class="mt-2" style="font-size:.8rem; opacity:.7;">
                                💡 Real websites are short, clean, and match the official brand name exactly.
                            </div>
                        </div>

                        <hr class="border-secondary my-4">

                        <!-- AI DEEP SCAN -->
                        <!-- <h6 class="text-uppercase fw-bold mb-2" style="color:#94a3b8; letter-spacing:.05em;">
                            <i class="bi bi-robot me-1" style="color:#60a5fa;"></i>
                            AI Deep Scan
                            <span class="badge ms-2" style="background:#1e3a5f; font-size:.68rem;">Gemini AI · ~5 sec</span>
                        </h6>
                        <form method="POST" id="aiForm">
                            <div class="input-group mb-1">
                                <input type="url" name="url" id="aiUrlInput"
                                       class="form-control bg-dark text-white border-secondary"
                                       placeholder="https://example.com" required
                                       value="<?php echo htmlspecialchars($scanned_url); ?>">
                                <button type="submit" class="btn btn-primary fw-bold" id="scanBtn">
                                    <span class="spinner-border spinner-border-sm visually-hidden" id="loadingSpinner"></span>
                                    <span id="btnText"><i class="bi bi-robot me-1"></i>AI Scan</span>
                                    <span class="visually-hidden" id="loadingText">Scanning…</span>
                                </button>
                            </div>
                            <small class="text-muted">Deeper analysis via Gemini AI — takes a few seconds</small>
                        </form> -->

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
                                AI RISK LEVEL: <?php echo $riskLabel; ?>
                            </div>

                            <h6><i class="bi bi-link-45deg me-1"></i>Scanned URL</h6>
                            <div class="url-display mb-3"><?php echo htmlspecialchars($scanned_url); ?></div>

                            <?php if (!empty($ai_analysis['reasons'])): ?>
                            <div class="ai-box mb-3">
                                <h6><i class="bi bi-robot me-2"></i>AI Detection Reasons</h6>
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
                                <strong>Advice:</strong> <?php echo htmlspecialchars($ai_analysis['advice']); ?>
                            </div>
                            <?php endif; ?>

                            <div class="alert alert-warning mb-3">
                                <i class="bi bi-shield-exclamation me-2"></i>
                                Never enter passwords or personal data on suspicious sites.
                            </div>
                            <div class="text-center">
                                <a href="url.php" class="btn btn-secondary me-2">
                                    <i class="bi bi-arrow-left me-1"></i>Scan Another
                                </a>
                                <a href="index.php" class="btn btn-outline-secondary">
                                    <i class="bi bi-house me-1"></i>Home
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
                <div>© 2026 Scam Detection Platform – BTEC FPT</div>
                <div>
                    <a href="#" class="footer-link">Privacy Policy</a>
                    &middot;
                    <a href="#" class="footer-link">Terms & Conditions</a>
                </div>
            </div>
        </div>
    </footer>

<script>
/* =====================================================
   QUICK SCAN — mirrors url_tracking1.html logic
   ===================================================== */
function quickScan() {
    const raw = document.getElementById('quickUrlInput').value.trim();
    if (!raw) { alert('Please enter a URL first.'); return; }

    // Sync into AI input
    document.getElementById('aiUrlInput').value = raw;

    const url = raw.toLowerCase();
    let score = 0, reasons = [];

    if (!url.startsWith('https')) {
        score += 20;
        reasons.push('🔓 Not using HTTPS — data could be intercepted.');
    }
    if (url.length > 40) {
        score += 10;
        reasons.push('📏 Unusually long URL — scammers hide suspicious content in long links.');
    }
    const scamWords = ['verify','login','bank','update','free','urgent','secure','confirm','account','password','signin'];
    for (const w of scamWords) {
        if (url.includes(w)) {
            score += 30;
            reasons.push(`⚠️ Contains suspicious keyword "${w}" — common in phishing URLs.`);
            break;
        }
    }
    if (url.includes('-') || url.includes('@')) {
        score += 20;
        reasons.push('🌐 Contains special characters ("-" or "@") — unusual for legitimate sites.');
    }
    if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(url)) {
        score += 30;
        reasons.push('🖥️ Uses an IP address instead of a domain name — a major red flag.');
    }
    const badTLDs = ['.xyz','.tk','.ml','.ga','.cf','.gq','.top','.click','.loan'];
    for (const t of badTLDs) {
        if (url.includes(t)) { score += 20; reasons.push(`🚩 Suspicious domain extension "${t}".`); break; }
    }

    score = Math.min(score, 100);

    // SRS FR4.2: Low 0-33%, Medium 34-66%, High 67-100%
    let level, status, confidence;
    if      (score === 0)  { level='low';    status='🟢 Extremely Safe'; confidence='90% – 95%'; }
    else if (score <= 33)  { level='low';    status='🟢 Low Risk';       confidence='85% – 90%'; }
    else if (score <= 66)  { level='medium'; status='🟠 Medium Risk';    confidence='80% – 85%'; }
    else                   { level='high';   status='🔴 High Risk';      confidence='85% – 90%'; }

    const finalReasons = reasons.length ? reasons : [
        '🟢 No suspicious patterns detected.',
        '🔒 Using secure HTTPS connection.',
        '🌐 Link looks clean and legitimate.'
    ];

    // SRS FR4.3: threshold-based recommendations
    let advice, action;
    if (score === 0) {
        advice = ['🟢 Highly trustworthy.', '🔍 No warning signs detected.'];
        action = ['✅ Safe to proceed.', '🔁 Stay alert in the future.'];
    } else if (score <= 33) {
        advice = ['🟢 Low risk — mostly looks safe.', '🔍 No strong risk signals.'];
        action = ['✅ Safe to use, but stay cautious.', '⚠️ Be careful with sensitive info.'];
    } else if (score <= 66) {
        advice = ['🟠 Medium risk — some warning signs.', '⚠️ Proceed with caution.'];
        action = ['⚠️ Do not enter personal information.', '🔎 Verify from official sources first.'];
    } else {
        advice = ['🔴 High risk — strong signs of danger.', '🚨 May try to steal your information.'];
        action = ['🚫 Do NOT use this website.', '🛑 Do not enter any passwords or personal data.'];
    }

    const bar = document.getElementById('quickBar');
    bar.style.width = score + '%';
    bar.style.background = score >= 67
        ? 'linear-gradient(90deg,#dc2626,#ef4444)'
        : score >= 34 ? 'linear-gradient(90deg,#f59e0b,orange)'
                      : 'linear-gradient(90deg,#16a34a,#22c55e)';

    document.getElementById('exampleBox').style.display = 'none';
    document.getElementById('quickResult').innerHTML = `
        <div class="quick-panel ${level}">
            <b>Status:</b> ${status} &nbsp;|&nbsp; <b>Score:</b> ${score}% &nbsp;|&nbsp; <b>Confidence:</b> ${confidence}
        </div>
        <div class="quick-panel ${level}"><b>Why this result?</b><br>${finalReasons.join('<br>')}</div>
        <div class="quick-panel ${level}"><b>What to do?</b><br>${[...advice,...action].join('<br>')}</div>`;

    if (score >= 67) {
        const toast = document.getElementById('alertToast');
        toast.style.display = 'block';
        try { new Audio('https://www.soundjay.com/buttons/beep-01a.mp3').play(); } catch(e) {}
        setTimeout(() => { toast.style.display = 'none'; }, 3500);
    }
}

/* =====================================================
   AI FORM — loading spinner
   ===================================================== */
const aiForm    = document.getElementById('aiForm');
const scanBtn   = document.getElementById('scanBtn');
const spinner   = document.getElementById('loadingSpinner');
const btnText   = document.getElementById('btnText');
const loadingText = document.getElementById('loadingText');

function resetBtn() {
    spinner.classList.add('visually-hidden');
    loadingText.classList.add('visually-hidden');
    btnText.classList.remove('visually-hidden');
    scanBtn.disabled = false;
}
resetBtn();
window.addEventListener('pageshow', resetBtn);
aiForm.addEventListener('submit', function () {
    if (!aiForm.checkValidity()) return;
    spinner.classList.remove('visually-hidden');
    loadingText.classList.remove('visually-hidden');
    btnText.classList.add('visually-hidden');
    scanBtn.disabled = true;
});

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