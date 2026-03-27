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
$GEMINI_API_KEY = 'AIzaSyAGVRQZcxlbK5fOSUMQkwhF9kKz1KOWY6c';
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
    $user_id  = $_SESSION['user_id']  ?? NULL;
    $username = $_SESSION['user_name'] ?? "Guest";
    $role     = $_SESSION['role']      ?? "Guest";

    // Normalise role to valid ENUM
    $allowed_roles = ["Admin","User","Employee","Guest"];
    if (!in_array($role, $allowed_roles)) {
        $role = "User";
    }

    // IP + UA with fallbacks
    if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $ip = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'])[0];
    } else {
        $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    }
    $browser = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';

    $stmt = $conn->prepare("
        INSERT INTO activity_logs
        (user_id, username, role, action, target, ip_address, user_agent)
        VALUES (?,?,?,?,?,?,?)
    ");

    if (!$stmt) {
        error_log("addLog prepare error (email.php): ".$conn->error);
        return;
    }

    $stmt->bind_param("issssss", $user_id, $username, $role, $action, $target, $ip, $browser);
    if (!$stmt->execute()) {
        error_log("addLog execute error (email.php): ".$stmt->error." user_id=".var_export($user_id,true));
    }
    $stmt->close();
}

/* =========================
GEMINI EMAIL ANALYSIS (scan.php style)
========================= */
function analyse_email_with_gemini(string $sender, string $subject, string $body, array $attachments, string $api_key): array {
    if (!$api_key) {
        return [
            'risk_level' => 'unknown',
            'reasons'    => ['Gemini API key not configured.'],
            'advice'     => 'AI analysis is unavailable. Be cautious with this email.'
        ];
    }

    $url = 'https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent';

    $attachmentDesc = empty($attachments)
        ? "none"
        : implode(', ', $attachments);

    global $lang;
    $languageInstruction = ($lang === 'vi')
        ? "Use short Vietnamese text for the reasons and advice fields."
        : "Use short English text for the reasons and advice fields.";

    $prompt = "You are a security assistant. Analyse the following email for phishing or scam.\n"
            . "Consider sender, subject, body and attachment types.\n"
            . $languageInstruction . "\n"
            . "Respond ONLY with a valid JSON object, no extra text, with this structure:\n"
            . "{\n"
            . "  \"risk_level\": \"low\" | \"medium\" | \"high\",\n"
            . "  \"reasons\": [\"short bullet reason 1\", \"short bullet reason 2\", ...],\n"
            . "  \"advice\": \"one short sentence of advice for the user\"\n"
            . "}\n";

    $emailDetails = "Sender: {$sender}\n"
                  . "Subject: {$subject}\n"
                  . "Attachments (types): {$attachmentDesc}\n"
                  . "Body:\n{$body}";

    $payload = [
        'contents' => [[
            'parts' => [
                ['text' => $prompt],
                ['text' => $emailDetails],
            ],
        ]],
        'generationConfig' => [
            'response_mime_type' => 'application/json',
        ],
    ];

    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL            => $url . '?key=' . urlencode($api_key),
        CURLOPT_POST           => true,
        CURLOPT_HTTPHEADER     => ['Content-Type: application/json'],
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POSTFIELDS     => json_encode($payload),
        CURLOPT_TIMEOUT        => 20,
    ]);

    $rawResponse = curl_exec($ch);
    if ($rawResponse === false) {
        $err = curl_error($ch);
        curl_close($ch);
        error_log('Gemini CURL error (email.php): '.$err);
        return [
            'risk_level' => 'unknown',
            'reasons'    => ['Failed to contact AI service (curl error).'],
            'advice'     => 'Try again later and be cautious with this email.'
        ];
    }
    curl_close($ch);

    $data = json_decode($rawResponse, true);

    if (isset($data['error'])) {
        $msg    = $data['error']['message'] ?? 'Unknown error from Gemini API.';
        $code   = $data['error']['code']    ?? 0;
        $status = $data['error']['status']  ?? '';

        // Log full error for debugging
        error_log('Gemini API error (email.php): '.json_encode($data));

        return [
            'risk_level' => 'unknown',
            'reasons'    => ["Gemini API error ({$code} {$status}): {$msg}"],
            'advice'     => 'AI analysis is temporarily unavailable. Be careful with this email.'
        ];
    }

    $text = $data['candidates'][0]['content']['parts'][0]['text'] ?? '';

    // 1) Try direct JSON
    $parsed = json_decode($text, true);

    // 2) Try to extract JSON object {...} from text
    if (!is_array($parsed) || !isset($parsed['risk_level'])) {
        if (preg_match('/\{.*\}/s', $text, $m)) {
            $parsed = json_decode($m[0], true);
        }
    }

    // 3) If JSON with risk_level, use it
    if (is_array($parsed) && isset($parsed['risk_level'])) {
        return [
            'risk_level' => $parsed['risk_level'] ?? 'unknown',
            'reasons'    => $parsed['reasons'] ?? [],
            'advice'     => $parsed['advice'] ?? '',
        ];
    }

    // 4) Fallback: infer level from keywords
    $lc = strtolower($text);
    $risk = 'unknown';
    if (strpos($lc, 'high risk') !== false || strpos($lc, 'very risky') !== false) {
        $risk = 'high';
    } elseif (strpos($lc, 'medium risk') !== false || strpos($lc, 'somewhat suspicious') !== false) {
        $risk = 'medium';
    } elseif (strpos($lc, 'low risk') !== false || strpos($lc, 'likely legitimate') !== false) {
        $risk = 'low';
    }

    return [
        'risk_level' => $risk,
        'reasons'    => [$text !== '' ? $text : 'AI returned an unexpected response.'],
        'advice'     => 'Be careful with this email. Do not click unknown links or provide personal data.'
    ];
}

/* =========================
GAMBLING POST-PROCESSING FOR EMAIL
========================= */
/**
 * Adjust AI analysis for gambling-related emails:
 * - Emails advertising or about gambling: at least medium risk.
 * - Add a clear gambling reason.
 */
function apply_gambling_rules_to_email(string $sender, string $subject, string $body, array $analysis): array {
    global $lang;

    $lowerSubject = strtolower($subject);
    $lowerBody    = strtolower($body);
    $lowerAll     = strtolower(
        implode(" ", $analysis['reasons'] ?? []) . " " .
        ($analysis['advice'] ?? '') . " " .
        $lowerSubject . " " . $lowerBody
    );

    $keywords = ['casino','bet','betting','sportsbook','slot','jackpot','poker','baccarat','roulette','bookmaker','wager','lotto','lottery','gamble','gambling'];
    $mentions = false;

    foreach ($keywords as $kw) {
        if (str_contains($lowerAll, $kw)) {
            $mentions = true;
            break;
        }
    }

    if (!$mentions) {
        return $analysis; // no gambling content detected
    }

    $risk = strtolower($analysis['risk_level'] ?? 'unknown');
    if ($risk === 'low' || $risk === 'unknown') {
        $risk = 'medium';
    }

    // Localised gambling reason/advice
    if ($lang === 'vi') {
        $reasonText = "Email này có nội dung liên quan đến cờ bạc/trò chơi cá cược trực tuyến, tiềm ẩn rủi ro tài chính và gây nghiện.";
        $defaultAdvice = "Hãy cẩn trọng với email liên quan đến cờ bạc, tránh nhấp vào liên kết hoặc cung cấp thông tin tài chính.";
    } else {
        $reasonText = "This email appears to be related to online gambling or betting promotions, which can pose financial and addiction risks.";
        $defaultAdvice = "Be cautious with gambling-related emails; avoid clicking links or sharing financial information.";
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
$analysis = null;
$email_address = '';
$email_subject = '';
$email_content = '';
$attachments = [];
$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email_address = trim($_POST['email_address'] ?? '');
    $email_subject = trim($_POST['email_subject'] ?? '');
    $email_content = trim($_POST['email_content'] ?? '');
    $attachments   = $_POST['attachments'] ?? [];

    if (!filter_var($email_address, FILTER_VALIDATE_EMAIL)) {
        $error = "Please enter a valid email address.";
    } elseif (empty($email_subject)) {
        $error = "Please enter the email subject.";
    } elseif (empty($email_content)) {
        $error = "Please enter the email content.";
    } else {
        // Log activity
        addLog($conn, "Email Scan", $email_address);

        // Save to search_history (using email_address as phonenumber field, scan_type = 'Email')
        if (isset($_SESSION['user_id'])) {
            $user_id = $_SESSION['user_id'];
            $stmt = $conn->prepare("
                INSERT INTO search_history (user_id, phonenumber, result_type, scan_type)
                VALUES (?, ?, ?, 'Email')
            ");
            // We'll set result_type after analysis; placeholder for now
            $placeholder_result = 'Pending';
            $stmt->bind_param("iss", $user_id, $email_address, $placeholder_result);
            $stmt->execute();
            $history_id = $conn->insert_id;
        }

        // Run Gemini analysis (risk_level: low | medium | high | unknown)
        $analysis = analyse_email_with_gemini(
            $email_address,
            $email_subject,
            $email_content,
            $attachments,
            $GEMINI_API_KEY
        );

        // Apply custom gambling rules (force at least medium, add reason)
        $analysis = apply_gambling_rules_to_email(
            $email_address,
            $email_subject,
            $email_content,
            $analysis
        );

        // Store risk_level directly as Low / Medium / High / Unknown
        $level = strtolower($analysis['risk_level']);
        if ($level !== 'low' && $level !== 'medium' && $level !== 'high') {
            $level = 'unknown';
        }
        $result_type = ucfirst($level); // "Low", "Medium", "High", "Unknown"

        // Update history record if we saved one
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
    .scan-card {
        background: rgba(0, 0, 0, 0.6);
        border-radius: 12px;
        padding: 30px;
        color: white;
    }
    .result-card {
        background: #ffffff;
        color: #000;
        border-radius: 12px;
        padding: 25px;
        margin-top: 25px;
        border: 5px solid transparent;
    }
    .border-high   { border-color: #dc3545; box-shadow: 0 0 20px rgba(220,53,69,0.4); }
    .border-medium { border-color: #fd7e14; box-shadow: 0 0 20px rgba(253,126,20,0.4); }
    .border-low    { border-color: #28a745; box-shadow: 0 0 20px rgba(40,167,69,0.4); }
    .border-unknown{ border-color: #6c757d; box-shadow: 0 0 20px rgba(108,117,125,0.4); }
    .risk-banner {
        color: white;
        font-size: 24px;
        font-weight: bold;
        text-align: center;
        padding: 15px;
        border-radius: 8px;
        margin-bottom: 20px;
    }
    .risk-high    { background: #dc3545; }
    .risk-medium  { background: #fd7e14; }
    .risk-low     { background: #28a745; }
    .risk-unknown { background: #6c757d; }
    .ai-box {
        background: #f8f9fa;
        border-left: 5px solid #0d6efd;
        padding: 20px;
        border-radius: 8px;
    }
    .footer-custom { background: rgba(0,0,0,0.75); color: white; }
    .footer-link { color: #ddd; text-decoration: none; }
    .footer-link:hover { color: white; text-decoration: underline; }

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
                <ul class="navbar-nav me-auto mb-2 mb-lg-0 mx-4 gap-5 fs-6">
                    <li class="nav-item"><a class="nav-link" href="index.php"><?php echo t("HOME");?></a></li>
                    <li class="nav-item"><a class="nav-link" href="phonenumber.php"><?php echo t("PHONE NUMBER");?></a></li>
                    <li class="nav-item"><a class="nav-link" href="url.php"><?php echo t("URL");?></a></li>
                    <li class="nav-item"><a class="nav-link active" href="email.php"><?php echo t("EMAIL");?></a></li>
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
                    <a href="login.php" class="btn btn-outline-info"><?php echo t("Sign in");?></a>
                    <a href="register.php" class="btn btn-outline-info"><?php echo t("Sign up");?></a>
                    <?php endif; ?>
                </div>
            </div>
        </div>
    </nav>

    <!-- MAIN CONTENT -->
    <div class="overlay">
        <div class="container mt-5 pt-5">
            <h2 class="text-center mb-4 mt-4"><?php echo t("Email Scan");?></h2>

            <?php if ($error): ?>
            <div class="alert alert-danger text-center"><?php echo htmlspecialchars(t($error)); ?></div>
            <?php endif; ?>

            <div class="row justify-content-center">
                <div class="col-md-8 col-lg-7">
                    <div class="scan-card">

                        <h6 class="text-uppercase fw-bold mb-2" style="color:#94a3b8; letter-spacing:.05em;">
                            <i class="bi bi-robot me-1" style="color:#60a5fa;"></i>
                            <?php echo t("Email Scan");?>
                            <span class="badge ms-2" style="background:#1e3a5f; font-size:.68rem;">~5 sec</span>
                        </h6>

                        <form method="POST" id="emailForm">
                            <div class="mb-3">
                                <label class="form-label"><?php echo t("Sender Email Address");?></label>
                                <input type="email" class="form-control" name="email_address"
                                    placeholder="sender@example.com" required
                                    value="<?php echo htmlspecialchars($email_address); ?>">
                            </div>

                            <div class="mb-3">
                                <label class="form-label"><?php echo t("Email Subject");?></label>
                                <input type="text" class="form-control" name="email_subject"
                                    placeholder="Subject line shown in your inbox" required
                                    value="<?php echo htmlspecialchars($email_subject); ?>">
                            </div>

                            <div class="mb-3">
                                <label class="form-label"><?php echo t("Attachments (if any)");?></label>
                                <div class="form-check">
                                    <input class="form-check-input" type="checkbox" value="image" name="attachments[]"
                                        <?php echo in_array('image', $attachments) ? 'checked' : ''; ?>>
                                    <label class="form-check-label"><?php echo t("Images (JPG, PNG, etc.)");?></label>
                                </div>
                                <div class="form-check">
                                    <input class="form-check-input" type="checkbox" value="pdf" name="attachments[]"
                                        <?php echo in_array('pdf', $attachments) ? 'checked' : ''; ?>>
                                    <label class="form-check-label"><?php echo t("Documents (PDF, DOCX, etc.)");?></label>
                                </div>
                                <div class="form-check">
                                    <input class="form-check-input" type="checkbox" value="executable" name="attachments[]"
                                        <?php echo in_array('executable', $attachments) ? 'checked' : ''; ?>>
                                    <label class="form-check-label"><?php echo t("Executable files (.exe, .zip, etc.)");?></label>
                                </div>
                                <div class="form-check">
                                    <input class="form-check-input" type="checkbox" value="other" name="attachments[]"
                                        <?php echo in_array('other', $attachments) ? 'checked' : ''; ?>>
                                    <label class="form-check-label"><?php echo t("Other / unknown file type");?></label>
                                </div>
                                <small class="text-muted">
                                    <?php echo t("You don’t need to upload files, just tell us what types were attached.");?>
                                </small>
                            </div>

                            <div class="mb-3">
                                <label class="form-label"><?php echo t("Email Body Content");?></label>
                                <textarea class="form-control" name="email_content" rows="6"
                                    placeholder="Paste the full email body here..." required><?php echo htmlspecialchars($email_content); ?></textarea>
                            </div>

                            <button type="submit" class="btn btn-primary w-100" id="scanBtn">
                                <span class="spinner-border spinner-border-sm visually-hidden" id="loadingSpinner"></span>
                                <span id="btnText"><i class="bi bi-envelope-open me-2"></i><?php echo t("Scan Email");?></span>
                                <span class="visually-hidden" id="loadingText"><?php echo t("Scanning...");?></span>
                            </button>

                        </form>
                    </div>

                    <!-- RESULTS -->
                    <?php if ($analysis): ?>
                    <?php
                        $level = strtolower($analysis['risk_level']); // low/medium/high/unknown

                        // Border/banner classes
                        $borderClass = "border-$level";
                        $bannerClass = "risk-$level";

                        // Icon stays the same
                        $riskIcon = $level === 'high' ? 'bi-exclamation-triangle-fill' :
                                   ($level === 'medium' ? 'bi-exclamation-circle-fill' :
                                   ($level === 'low' ? 'bi-shield-check-fill' : 'bi-question-circle-fill'));

                        // Localised label
                        if ($lang === 'vi') {
                            if ($level === 'high') {
                                $riskLabel = 'Cao';
                            } elseif ($level === 'medium') {
                                $riskLabel = 'Trung Bình';
                            } elseif ($level === 'low') {
                                $riskLabel = 'Thấp';
                            } else {
                                $riskLabel = 'Không xác định';
                            }
                        } else {
                            // English: KEEP original uppercase codes
                            $riskLabel = strtoupper($analysis['risk_level']);
                        }
                    ?>
                    <div class="result-card <?php echo $borderClass; ?>">

                        <div class="risk-banner <?php echo $bannerClass; ?>">
                            <i class="bi <?php echo $riskIcon; ?> me-2"></i>
                            <?php echo t("Risk Level:");?> <?php echo $riskLabel; ?>
                        </div>

                        <?php if (!empty($analysis['reasons'])): ?>
                        <div class="ai-box mb-3">
                            <h5><i class="bi bi-robot me-2"></i><?php echo t("AI Detection Reasons");?></h5>
                            <ul class="mb-0">
                                <?php foreach ($analysis['reasons'] as $reason): ?>
                                <li><?php echo htmlspecialchars($reason); ?></li>
                                <?php endforeach; ?>
                            </ul>
                        </div>
                        <?php endif; ?>

                        <?php if (!empty($analysis['advice'])): ?>
                            <div class="alert alert-info">
                                <i class="bi bi-lightbulb me-2"></i>
                                <strong><?php echo t("Advice:");?></strong> <?php echo htmlspecialchars($analysis['advice']); ?>
                            </div>
                        <?php endif; ?>

                        <hr>
                        <h5><i class="bi bi-envelope me-2"></i><?php echo t("Scanned Email Details");?></h5>
                        <p><strong><?php echo t("From:");?></strong> <?php echo htmlspecialchars($email_address); ?></p>
                        <p><strong><?php echo t("Subject:");?></strong> <?php echo htmlspecialchars($email_subject); ?></p>
                        <p><strong><?php echo t("Attachments:");?></strong>
                            <?php echo empty($attachments) ? 'None' : htmlspecialchars(implode(', ', $attachments)); ?>
                        </p>
                        <div class="bg-light p-3 rounded">
                            <pre style="white-space:pre-wrap; word-break:break-word; font-size:0.9rem; margin:0;"><?php echo htmlspecialchars($email_content); ?></pre>
                        </div>

                        <div class="mt-3">
                            <small class="text-muted">
                                This information is provided for reference purposes only and should not be considered absolute.
                                We do not guarantee the accuracy of the results and are not responsible for decisions made based on this information.
                            </small>
                        </div>

                        <div class="text-center mt-3">
                            <a href="email.php" class="btn btn-secondary me-2">
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
    const form = document.getElementById('emailForm');
    const btn = document.getElementById('scanBtn');
    const spinner = document.getElementById('loadingSpinner');
    const btnText = document.getElementById('btnText');
    const loadingText = document.getElementById('loadingText');

    function resetBtn() {
        spinner.classList.add('visually-hidden');
        loadingText.classList.add('visually-hidden');
        btnText.classList.remove('visually-hidden');
        btn.disabled = false;
    }

    resetBtn();
    window.addEventListener('pageshow', resetBtn);

    form.addEventListener('submit', function () {
        if (!form.checkValidity()) return;
        spinner.classList.remove('visually-hidden');
        loadingText.classList.remove('visually-hidden');
        btnText.classList.add('visually-hidden');
        btn.disabled = true;
    });
    </script>
</body>
</html>
</html>