<?php
declare(strict_types=1);

header('Content-Type: application/x-ndjson; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('X-Content-Type-Options: nosniff');

function respondWithHistoryError(int $statusCode, string $message): void
{
    http_response_code($statusCode);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(['error' => $message], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'GET') {
    header('Allow: GET');
    respondWithHistoryError(405, 'Method not allowed. Use GET.');
}

$apiToken = $_GET['api_token'] ?? null;
$deviceId = $_GET['device'] ?? null;
if (!is_string($apiToken) || $apiToken === '' || strlen($apiToken) > 256) {
    respondWithHistoryError(403, 'Forbidden. Invalid API token.');
}
if (!is_string($deviceId) || !preg_match('/\A[a-zA-Z0-9_-]{1,64}\z/', $deviceId)) {
    respondWithHistoryError(400, 'Missing or invalid device ID.');
}

require_once __DIR__ . '/../includes/device_history.php';

try {
    require __DIR__ . '/../config/db.php';

    $userStatement = $pdo->prepare('SELECT id FROM users WHERE api_token = :api_token LIMIT 1');
    $userStatement->execute([':api_token' => $apiToken]);
    $userId = $userStatement->fetchColumn();
    if ($userId === false) {
        respondWithHistoryError(403, 'Forbidden. Invalid API token.');
    }

    $settingsStatement = $pdo->prepare(
        'SELECT settings.enabled, settings.retention_seconds '
        . 'FROM user_devices AS ud '
        . 'INNER JOIN device_history_settings AS settings ON settings.device_id = ud.device_id '
        . 'WHERE ud.user_id = :user_id AND ud.device_id = :device_id'
    );
    $settingsStatement->execute([':user_id' => (int) $userId, ':device_id' => $deviceId]);
    $settings = $settingsStatement->fetch(PDO::FETCH_ASSOC);
    if (!$settings) {
        respondWithHistoryError(404, 'Device history not found.');
    }
    if ((int) $settings['enabled'] !== 1) {
        respondWithHistoryError(404, 'Device history is disabled.');
    }

    echo readRetainedDeviceHistory(
        dirname(__DIR__) . '/storage',
        $deviceId,
        (int) $settings['retention_seconds'],
        time()
    );
} catch (PDOException $error) {
    error_log('Device history API database operation failed: ' . $error->getMessage());
    respondWithHistoryError(500, 'Database operation failed.');
} catch (RuntimeException $error) {
    error_log('Device history API storage operation failed: ' . $error->getMessage());
    respondWithHistoryError(500, 'Could not read device history.');
}
