<?php
/**
 * Gọi API Google Translate để dịch text
 * @param string $text Text gốc tiếng Anh
 * @param string $target Mã ngôn ngữ đích (ví dụ 'vi')
 * @return string Text đã dịch
 */
function translateText($text, $target = 'vi') {
    // URL API dịch
    $url = "https://translate.googleapis.com/translate_a/single?client=gtx&sl=en&tl=" . $target . "&dt=t&q=" . urlencode($text);

    $options = [
        "http" => [
            "method" => "GET",
            "header" => "User-Agent: Mozilla/5.0\r\n"
        ]
    ];

    $context = stream_context_create($options);
    $result = @file_get_contents($url, false, $context); // @ để ẩn lỗi nếu API sập

    if ($result === false) return $text;

    $data = json_decode($result, true);
    return $data[0][0][0] ?? $text;
}

/**
 * Hàm dịch text theo session lang
 * @param string $text Text gốc tiếng Anh
 * @return string Text đã dịch
 */
function t($text) {
    $lang = $_SESSION['lang'] ?? 'en';

    // Nếu ngôn ngữ hiện tại là EN hoặc text rỗng → trả về text gốc
    if ($lang == 'en' || empty($text)) return $text;

    $cacheDir = __DIR__ . "/languages";
    if (!is_dir($cacheDir)) {
        mkdir($cacheDir, 0777, true); // tạo folder nếu chưa có
    }

    $cacheFile = $cacheDir . "/cache_vi.json";

    // Đọc cache hiện tại
    $cache = [];
    if (file_exists($cacheFile)) {
        $cache = json_decode(file_get_contents($cacheFile), true);
    }

    // Nếu text đã có trong cache → trả luôn
    if (isset($cache[$text])) {
        return $cache[$text];
    }

    // Nếu chưa có trong cache → gọi API
    $translated = translateText($text, 'vi');

    // Lưu vào cache
    if ($translated !== $text) {
        $cache[$text] = $translated;
        file_put_contents($cacheFile, json_encode($cache, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT));
    }

    return $translated;
}