<?php
require_once __DIR__ . '/../vendor/autoload.php';

$dotenv = Dotenv\Dotenv::createImmutable(__DIR__);
$dotenv->load();

session_start();
require_once '../Database/database.php';

/* =========================
GET PHONE
========================= */

$phone=$_GET['phone'] ?? '';
$phone=preg_replace('/\D/','',$phone);

if(!$phone){
die("Phone number not provided");
}


/* =========================
VIETNAM PHONE NORMALIZATION
========================= */

if(substr($phone,0,2)=="84"){
$phone="0".substr($phone,2);
}

if(substr($phone,0,4)=="0084"){
$phone="0".substr($phone,4);
}

if(!preg_match('/^(0\d{9}|1900\d{4})$/', $phone)){
    die("Invalid Vietnam phone number");
}


/* =========================
NUMVERIFY API
========================= */

$carrier = "Unknown";
$number_type = "Unknown";
$numverify_valid = false;
$numverify_carrier = "";
$numverify_line_type = "";

$stmt = $conn->prepare("SELECT carrier, type FROM phone_metadata WHERE phone = ? AND updated_at > NOW() - INTERVAL 7 DAY LIMIT 1");
$stmt->bind_param("s", $phone);
$stmt->execute();
$result = $stmt->get_result();

$from_cache = false;

if ($row = $result->fetch_assoc()) {
    $carrier = $row['carrier'];
    $number_type = $row['type'];
    $from_cache = true;
} else {
    $access_key = getenv("NUMVERIFY_API_KEY");
    if ($access_key) {
        $api_url = "http://apilayer.net/api/validate?access_key={$access_key}&number={$phone}&country_code=VN&format=1";
$context = stream_context_create([
    'http' => [
        'timeout' => 3
    ]
]);

$response = @file_get_contents($api_url, false, $context);        if ($response !== false) {
            $numverify = json_decode($response, true);
            $numverify_valid = $numverify['valid'] ?? false;
            $numverify_carrier = $numverify['carrier'] ?? "";
            $numverify_line_type = $numverify['line_type'] ?? "";
            
            // Cập nhật giá trị để lưu vào DB
            $carrier = !empty($numverify_carrier) ? $numverify_carrier : $carrier;
if($numverify_line_type == "mobile"){
        $number_type = "Mobile";
    } elseif($numverify_line_type == "landline"){
        $number_type = "Landline";
    }        }
    }
}

/* =========================
PREFIX
========================= */

$prefix3 = substr($phone,0,3);
$prefix4 = substr($phone,0,4);


/* =========================
DEFAULT TYPE
========================= */
if($number_type == "Unknown"){
    if($prefix3 == "024" || $prefix3 == "028"){
        $number_type = "Landline";
    } else {
        $number_type = "Mobile";
    }
}

/* =========================
CARRIER DETECTION
========================= */

$carriers=[

"Viettel"=>["032","033","034","035","036","037","038","039","086","096","097","098"],
"Vinaphone"=>["081","082","083","084","085","088","091","094"],
"Mobifone"=>["070","076","077","078","079","089","090","093"],
"Vietnamobile"=>["092","056","058"],
"Gmobile"=>["099","059"],
"Itelecom"=>["087"]

];

if($carrier == "Unknown"){
    foreach($carriers as $name=>$list){
        if(in_array($prefix3,$list)){
            $carrier=$name;
            break;
        }
    }
}

/* =========================
OVERRIDE WITH NUMVERIFY
========================= */
if($numverify_valid){
    if(!empty($numverify_carrier)){
        $carrier = $numverify_carrier;
    }

    if($numverify_line_type == "mobile"){
        $number_type = "Mobile";
    } elseif($numverify_line_type == "landline"){
        $number_type = "Landline";
    }
}

if($prefix4=="1900"){
$number_type="Premium Service";
}

$country="Vietnam";

// =========================
// SAVE CACHE (MOVE HERE)
// =========================
if(!$from_cache){
    $stmt = $conn->prepare("
    INSERT INTO phone_metadata (phone, carrier, type, updated_at)
    VALUES (?, ?, ?, NOW())
    ON DUPLICATE KEY UPDATE 
    carrier=VALUES(carrier), 
    type=VALUES(type), 
    updated_at=NOW()
    ");
    $stmt->bind_param("sss", $phone, $carrier, $number_type);
    $stmt->execute();
}

/* =========================
ADMIN PHONE CHECK
========================= */

$stmt = $conn->prepare("SELECT * FROM phonenumbers WHERE phonenumber = ?");
$stmt->bind_param("s", $phone);
$stmt->execute();
$res_admin = $stmt->get_result();
$admin_flag = false;
$admin_description = "";
if($row = $res_admin->fetch_assoc()){
    $admin_flag = true;
    $admin_description = $row['description'] ?? "";
}


/* =========================
USER REPORTS
========================= */

$stmt = $conn->prepare("SELECT report_reason FROM reports WHERE phone = ?");
$stmt->bind_param("s", $phone);
$stmt->execute();
$res_reports = $stmt->get_result();
$db_reports = 0;
$report_types = [];
while($row = $res_reports->fetch_assoc()){
    $db_reports++;
    $report_types[] = $row['report_reason'];
}
$report_types = array_unique($report_types);


/* =========================
RISK CALCULATION
========================= */

$risk_score=0;

if($admin_flag){
$risk_score=90;
}else{

if($db_reports>=5){
$risk_score+=40;
}elseif($db_reports>=3){
$risk_score+=25;
}elseif($db_reports>=1){
$risk_score+=15;
}

if(in_array($prefix3,["089","088","086"])){
$risk_score+=10;
}

if(in_array($prefix3,["024","028"])){
$risk_score+=5;
}

if($prefix4=="1900"){
$risk_score+=25;
}

if(preg_match('/(\d)\1{3,}/',$phone)){
$risk_score+=15;
}

if(preg_match('/1234|2345|3456|4567|5678|6789|1111|2222|3333/',$phone)){
$risk_score+=10;
}

$risk_score=min($risk_score,100);
}

/* =========================
STATUS ENGINE
========================= */

$status_text="SAFE";
$status_class="scam-banner-green";
$status_desc="No scam activity detected.";
$status_icon=' <svg xmlns="http://www.w3.org/2000/svg" height="40" viewBox="0 -960 960 960" width="40" fill="#41d24b"> <path d="m421-298 283-283-46-45-237 237-120-120-45 45 165 166Z"/> </svg> ';

if($admin_flag){

    $status_text="SCAM";
    $status_class="scam-banner-red";
    $status_desc="This number is flagged by system admin as dangerous.";
    $status_icon='<svg xmlns="http://www.w3.org/2000/svg" height="48px" viewBox="0 -960 960 960" width="48px" fill="#FFFFFF"><path d="M480-281q14 0 24.5-10.5T515-316q0-14-10.5-24.5T480-351q-14 0-24.5 10.5T445-316q0 14 10.5 24.5T480-281Zm-30-144h60v-263h-60v263ZM330-120 120-330v-300l210-210h300l210 210v300L630-120H330Zm25-60h250l175-175v-250L605-780H355L180-605v250l175 175Zm125-300Z"/></svg> ';

}
elseif($db_reports==0){

$status_text="NO DATA";
$status_class="scam-banner-gray";
$status_desc="No scam reports have been found for this number yet.";
$status_icon='<svg xmlns="http://www.w3.org/2000/svg" height="40px" viewBox="0 -960 960 960" width="40px" fill="#FFFF55"><path d="M505.17-290.15q10.16-10.16 10.16-25.17 0-15.01-10.15-25.18-10.16-10.17-25.17-10.17-15.01 0-25.18 10.16-10.16 10.15-10.16 25.17 0 15.01 10.15 25.17Q464.98-280 479.99-280q15.01 0 25.18-10.15Zm-56.5-145.18h66.66V-684h-66.66v248.67ZM480.18-80q-82.83 0-155.67-31.5-72.84-31.5-127.18-85.83Q143-251.67 111.5-324.56T80-480.33q0-82.88 31.5-155.78Q143-709 197.33-763q54.34-54 127.23-85.5T480.33-880q82.88 0 155.78 31.5Q709-817 763-763t85.5 127Q880-563 880-480.18q0 82.83-31.5 155.67Q817-251.67 763-197.46q-54 54.21-127 85.84Q563-80 480.18-80Zm.15-66.67q139 0 236-97.33t97-236.33q0-139-96.87-236-96.88-97-236.46-97-138.67 0-236 96.87-97.33 96.88-97.33 236.46 0 138.67 97.33 236 97.33 97.33 236.33 97.33ZM480-480Z"/></svg>';

}
elseif($risk_score>=70){

$status_text="SCAM";
$status_class="scam-banner-red";
$status_desc="This number has strong indicators of scam activity.";
$status_icon='<svg xmlns="http://www.w3.org/2000/svg" height="48px" viewBox="0 -960 960 960" width="48px" fill="#FFFFFF"><path d="M480-281q14 0 24.5-10.5T515-316q0-14-10.5-24.5T480-351q-14 0-24.5 10.5T445-316q0 14 10.5 24.5T480-281Zm-30-144h60v-263h-60v263ZM330-120 120-330v-300l210-210h300l210 210v300L630-120H330Zm25-60h250l175-175v-250L605-780H355L180-605v250l175 175Zm125-300Z"/></svg> ';

}
elseif($risk_score>=40){

$status_text="SUSPICIOUS";
$status_class="scam-banner-orange";
$status_desc="This number may be suspicious based on community reports.";
$status_icon=' <svg xmlns="http://www.w3.org/2000/svg" height="40" viewBox="0 -960 960 960" width="40" fill="#facc15"> <path d="M480-280q17 0 28.5-11.5T520-320q0-17-11.5-28.5T480-360q-17 0-28.5 11.5T440-320q0 17 11.5 28.5T480-280Zm-40-120h80v-280h-80v280Z"/> </svg> ';

}

/* =========================
AI ANALYSIS FUNCTION (GEMINI)
========================= */
function generateAI($phone, $carrier, $country, $reports, $risk, $type, $report_types, $admin_flag) {
    $api_key = $_ENV['GEMINI_API_KEY'] ?? ''; // Ensure this is set in your environment
    
    if(!$api_key){
    return "AI KEY NOT FOUND";
}

    // Using Gemini 1.5 Flash (Fast & Free Tier)
$url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-3-flash-preview:generateContent?key=" . $api_key;
    $types = !empty($report_types) ? implode(", ", $report_types) : "No specific types reported";
    $admin_status = $admin_flag ? "FLAGGED AS DANGEROUS BY ADMIN" : "Neutral";

    $prompt = "You are a cyber-security expert specializing in telecommunications fraud. 
    Analyze the following phone number: $phone.
    
    System Data:
    - Carrier: $carrier
    - Line Type: $type
    - Community Reports: $reports
    - System Risk Score: $risk%
    - Admin Status: $admin_status
    - Reported Violations: $types

    Task: Write a detailed security report in English including:
    1. Risk Summary: Why is this number flagged? (e.g., VOIP usage, high report count).
    2. Risk Level: (SAFE / SUSPICIOUS / SCAM) and the reasoning.
    3. Safety Advice: 2-3 practical tips for the user.
    Format the output using basic HTML (<b>, <p>, <ul>).";

    $data = [
        "contents" => [["parts" => [["text" => $prompt]]]]
    ];

    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, ["Content-Type: application/json"]);
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));

    $res = curl_exec($ch);

if($res === false){
    return "CURL ERROR: " . curl_error($ch);
}

$json = json_decode($res, true);
curl_close($ch);

// DEBUG FULL RESPONSE
if(isset($json['error'])){
    return "API ERROR: " . $json['error']['message'];
}

if(!isset($json['candidates'][0]['content']['parts'][0]['text'])){
    return "<pre>" . print_r($json, true) . "</pre>";
}

return $json['candidates'][0]['content']['parts'][0]['text'];
}


/* =========================
CARD BORDER COLOR
========================= */

$card_border="border-safe";

if($risk_score>=70){
$card_border="border-scam";
}
elseif($risk_score>=40){
$card_border="border-warning";
}
elseif($db_reports==0){
$card_border="border-unknown";
}

/* =========================
AI CACHING LOGIC
========================= */
$stmt = $conn->prepare("
SELECT ai_result FROM risk_analysis 
WHERE phone = ? 
AND ABS(risk_score - ?) < 15
AND created_at > NOW() - INTERVAL 7 DAY
ORDER BY created_at DESC 
LIMIT 1
");
$stmt->bind_param("si", $phone, $risk_score);
$stmt->execute();
$res_ai = $stmt->get_result();

if($row = $res_ai->fetch_assoc()){
    $ai_explanation = $row['ai_result'];
} else {
    // Call AI and save result
    $ai_explanation = generateAI($phone, $carrier, $country, $db_reports, $risk_score, $number_type, $report_types, $admin_flag);
    
    $stmt_save = $conn->prepare("INSERT INTO risk_analysis (phone, risk_score, ai_result) VALUES (?,?,?)");
    $stmt_save->bind_param("sis", $phone, $risk_score, $ai_explanation);
    $stmt_save->execute();
}

/* =========================
REPORT SYSTEM
========================= */

if(isset($_POST['report'])){

$reason = trim($_POST['reason']);

if(empty($reason)){
    die("Invalid report");
}

$comment = trim($_POST['comment']);

$stmt=$conn->prepare("
INSERT INTO reports (phone,report_reason,comment)
VALUES (?,?,?)
");

$stmt->bind_param("sss",$phone,$reason,$comment);
$stmt->execute();

header("Location: result.php?phone=".$phone);
exit;

}

?>

<!DOCTYPE html>
<html>

<head>

    <title>Phone Check Result</title>

    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/css/bootstrap.min.css" rel="stylesheet">

    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css">

    <style>
    body {
        background-image: url("img/background.png");
        background-size: cover;
        background-position: center;
        background-attachment: fixed;
        font-family: Arial;
    }

    .overlay {
        background: rgba(0, 0, 0, 0.55);
        min-height: 100vh;
        display: flex;
        justify-content: center;
        align-items: center;
        padding-top: 120px;
    }

    .result-card {
        width: 900px;
        max-width: 95%;
        background: white;
        border-radius: 12px;
        box-shadow: 0 0 25px rgba(0, 0, 0, 0.5);
        padding: 30px;
        border: 6px solid transparent;
        outline: 3px solid rgba(0, 0, 0, 0.1);
    }

    /*scam */
    .border-scam {
        border-color: #e72337;
        box-shadow: 0 0 25px rgba(220, 53, 69, 0.5);
    }

    /* suspicious */

    .border-warning {
        border-color: #fd7e14;
        box-shadow: 0 0 25px rgba(253, 126, 20, 0.4);
    }

    /* safe */

    .border-safe {
        border-color: #28a745;
        box-shadow: 0 0 25px rgba(40, 167, 69, 0.4);
    }

    /* unknown */

    .border-unknown {
        border-color: #6c757d;
        box-shadow: 0 0 25px rgba(108, 117, 125, 0.4);
    }

    .result-header {

        background: black;
        color: white;
        font-weight: bold;
        text-align: center;
        padding: 18px;
        margin: -30px -30px 30px -30px;

        display: flex;
        align-items: center;
        justify-content: center;
        gap: 12px;

    }

    /* chữ header */

    .header-text {

        letter-spacing: 3px;
        font-size: 25px;

    }

    .phone-number {

        font-size: 50px;
        text-align: center;
        font-weight: bold;
        letter-spacing: 3px;

    }

    .scam-banner {

        color: white;
        font-size: 30px;
        text-align: center;
        padding: 15px;
        border-radius: 8px;
        margin: 20px auto;
        width: fit-content;
        min-width: 300px;

    }

    .scam-banner-red {
        background: #f8071f;
    }

    .scam-banner-orange {
        background: #fd7e14;
    }

    .scam-banner-green {
        background: #28a745;
    }

    .scam-banner-gray {
        background: #6c757d;
    }

    .scam-text {

        text-align: center;
        margin-top: 10px;

    }

    .info-grid {
        display: grid;
        grid-template-columns: repeat(3, 1fr);
        gap: 20px;
        margin-top: 25px;
    }

    .info-item {

        background: #f3f4f6;
        padding: 9px;
        border-radius: 8px;
        text-align: center;

    }

    .community-box { 
        background: #fff3cd; 
        border-left: 6px solid #ff9800; 
        padding: 15px; 
        border-radius: 8px; 
    }

    .safety-box {

        background: #f8f9fa;
        border-left: 6px solid #6c757d;
        padding: 20px;
        border-radius: 8px;
        margin-top: 20px;

    }

    .ai-box {
        background: #f8f9fa;
        border-left: 5px solid #0d6efd;
        padding: 20px;
        border-radius: 8px;
        line-height: 1.6;
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

            <a class="navbar-brand fw-bold fs-3 me-5" href="index.php">SCAM PROOF</a>

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

    <div class="overlay">

        <div class="result-card <?php echo $card_border ?>">

            <div class="result-header">

                <svg xmlns="http://www.w3.org/2000/svg" height="60" viewBox="0 -960 960 960" width="60" fill="#EA3323">

                    <path
                        d="M480-81q-140-35-230-162.5T160-523v-238l320-120 320 120v238q0 152-90 279.5T480-81Zm0-62q115-38 187.5-143.5T740-523v-196l-260-98-260 98v196q0 131 72.5 236.5T480-143Zm0-337Zm-90 160h180q13 0 21.5-8.5T600-350v-140q0-13-8.5-21.5T570-520h-10v-40q0-33-23.5-56.5T480-640q-33 0-56.5 23.5T400-560v40h-10q-13 0-21.5 8.5T360-490v140q0 13 8.5 21.5T390-320Zm40-200v-40q0-20 15-33.5t35-13.5q20 0 35 13.5t15 33.5v40H430Z" />

                </svg>

                <span class="header-text">
                    PHONE NUMBER REGISTRY CHECK RESULT
                </span>

            </div>
            <h3 class="text-center mb-3 phone-number">

                <?php echo htmlspecialchars($phone); ?>

            </h3>


            <div class="scam-banner <?php echo $status_class ?> text-center p-3 text-white">
                <strong><?php echo $status_icon ?></strong>
                <strong><?php echo $status_text ?></strong>

            </div>


            <p class="text-center">

                <?php echo $status_desc ?>

            </p>


            <div class="info-grid">

                <div class="info-item">
                    <i class="bi bi-globe"></i>
                    <strong class="info-item">Country: </strong>
                    <?php echo $country ?>
                </div>

                <div class="info-item">
                    <i class="bi bi-broadcast"></i>
                    <strong class="info-item">Carrier Network: </strong>
                    <?php echo htmlspecialchars($carrier)?>
                </div>

                <div class="info-item">
                    <i class="bi bi-flag"></i>
                    <strong class="info-item">Community Reports: </strong>
                    <?php echo $db_reports ?>
                </div>

                <div class="info-item">
                    <i class="bi bi-telephone"></i>
                    <strong class="info-item">Phone Prefix: </strong>
                    <?php echo $prefix4=="1900" ? $prefix4 : $prefix3 ?>
                </div>

                <div class="info-item">
                    <i class="bi bi-phone"></i>
                    <strong class="info-item">Number Type: </strong>
                    <?php echo $number_type ?>
                </div>

                <div class="info-item">
                    <?php

                        $color="text-success";

                        if($risk_score>=70){
                        $color="text-danger";
                        }
                        elseif($risk_score>=40){
                        $color="text-warning";
                        }

                    ?>
                    <i class="bi bi-shield-exclamation"></i>
                    <strong class="info-item <?php echo $color ?>">Risk Score: </strong>
                    <?php echo $risk_score ?>%
                </div>

            </div>


            <div class="ai-box mt-4">
    <h5><i class="bi bi-robot"></i> AI Risk Analysis</h5>
    <div><?php echo strip_tags($ai_explanation, "<b><p><ul><li>"); ?></div>
</div>

            <div class="community-box mt-3">

<strong><i class="bi bi-people-fill"></i> Community Status</strong>

<?php if(empty($admin_description) && empty($report_types)): ?>

<p>No reports yet.</p>

<?php else: ?>

<?php if($admin_description): ?>
<p>
<i class="bi bi-bell-fill text-danger"></i>
<strong class="text-danger">Admin Warning:</strong>
<?php echo htmlspecialchars($admin_description); ?>
</p>
<?php endif; ?>

<?php if(!empty($report_types)): ?>
    <ul>
<?php foreach($report_types as $t){
echo "<li>".htmlspecialchars($t)."</li>";
} ?>
</ul>
<?php endif; ?>

<?php endif; ?>

</div>
        <div class="safety-box mt-3">

            <strong>
                <i class="bi bi-shield-check me-1"></i>
                Safety Advice
            </strong>

            <ul class="mt-2 mb-0">

                <li>Do not share OTP codes with unknown callers.</li>

                <li>Never transfer money to strangers.</li>

                <li>Verify the caller through official company channels.</li>

                <li>If the caller pressures you to act quickly, it may be a scam.</li>

            </ul>

        </div>

        <div class="mt-3">
            <small class="text-muted">
                This information is provided for reference purposes only and should not be considered absolute.
                We do not guarantee the accuracy of the results and are not responsible for decisions made based on this information.
            </small>
        </div>

        <div class="mt-4 text-center">

            <a href="phonenumber.php" class="btn btn-secondary">

                Back

            </a>

            <button onclick="showReport()" class="btn btn-danger">

                Report Number

            </button>

        </div>


        <div id="reportForm" style="display:none;margin-top:20px;">

            <form method="POST">

                <select name="reason" class="form-select mb-2">

                    <optgroup label="Financial Scams">
                        <option value="Bank Scam">Pretending to be a bank</option>
                        <option value="Loan Scam">Fake loan service</option>
                        <option value="Investment Scam">Fake investment</option>
                        <option value="Crypto Scam">Cryptocurrency scam</option>
                        <option value="Insurance Scam">Fake insurance offer</option>
                    </optgroup>

                    <optgroup label="Impersonation Scams">
                        <option value="Government Impersonation">Police/Government impersonation</option>
                        <option value="Tech Support Scam">Fake technical support</option>
                        <option value="Delivery Scam">Fake delivery problem</option>
                    </optgroup>

                    <optgroup label="Online Scams">
                        <option value="E-commerce Scam">Online shopping fraud</option>
                        <option value="Job Scam">Fake job recruitment</option>
                        <option value="Prize Scam">Fake lottery prize</option>
                    </optgroup>

                    <optgroup label="Spam / Other">
                        <option value="Spam Telemarketing">Telemarketing spam</option>
                        <option value="Robocall">Automated robocall</option>
                        <option value="Harassment">Harassment call</option>
                        <option value="Unknown Suspicious Call">Unknown suspicious call</option>
                    </optgroup>

                </select>

                <textarea name="comment" class="form-control" rows="3" placeholder="Describe the scam..."></textarea>

                <button type="submit" name="report" class="btn btn-danger mt-2">
                    Submit Report
                </button>

            </form>

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

<script>
function showReport() {

    var f = document.getElementById("reportForm");

    if (f.style.display == "none") {
        f.style.display = "block";
    } else {
        f.style.display = "none";
    }

}
</script> 