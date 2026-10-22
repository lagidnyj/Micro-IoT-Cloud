<?php
// Захист: перевірка токена читання (може бути окремий ключ для клієнтів)
$headers = getallheaders();
$authHeader = $headers['Authorization'] ?? $headers['authorization'] ?? '';
$expectedToken = 'ТВОЙ_СЕКРЕТНИЙ_КЛЮЧ_ДЛЯ_ЧИТАННЯ';

if ($authHeader !== 'Bearer ' . $expectedToken) {
    http_response_code(401);
    echo json_encode(["error" => "Unauthorized"]);
    exit;
}

// Визначаємо який пристрій хочемо прочитати
$deviceId = $_GET['device'] ?? '';
$deviceId = preg_replace('/[^a-zA-Z0-9_\-]/', '_', $deviceId);

$filePath = dirname(__DIR__) . '/storage/' . $deviceId . '.json';

if (!file_exists($filePath)) {
    http_response_code(404);
    echo json_encode(["error" => "Device data not found"]);
    exit;
}

// Віддаємо вміст JSON клієнту
header('Content-Type: application/json');
readfile($filePath);
