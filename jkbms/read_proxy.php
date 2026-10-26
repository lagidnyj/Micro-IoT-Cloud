<?php
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

function respondWithError(int $statusCode, string $message): void {
    http_response_code($statusCode);
    echo json_encode(['error' => $message], JSON_UNESCAPED_UNICODE);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    header('Allow: GET');
    respondWithError(405, 'Method not allowed. Use GET.');
}

$deviceId = $_GET['device'] ?? '';
if (!is_string($deviceId) || !preg_match('/\A[a-zA-Z0-9_-]{1,64}\z/', $deviceId)) {
    respondWithError(400, 'Invalid device ID.');
}

$configPath = __DIR__ . '/read_config.json';
$config = is_file($configPath) ? json_decode(file_get_contents($configPath), true) : null;
if (!is_array($config)
    || !isset($config['read_url'], $config['read_token'])
    || !is_string($config['read_url'])
    || !is_string($config['read_token'])
    || $config['read_token'] === ''
    || $config['read_token'] === 'REPLACE_WITH_READ_TOKEN'
) {
    respondWithError(500, 'Configure read_url and read_token in read_config.json.');
}

$urlParts = parse_url($config['read_url']);
if (filter_var($config['read_url'], FILTER_VALIDATE_URL) === false
    || !is_array($urlParts)
    || ($urlParts['scheme'] ?? '') !== 'https'
    || empty($urlParts['host'])
    || isset($urlParts['user'])
    || isset($urlParts['pass'])
    || isset($urlParts['query'])
    || isset($urlParts['fragment'])
) {
    respondWithError(500, 'read_url must be an HTTPS endpoint without query parameters.');
}

if (!function_exists('curl_init')) {
    respondWithError(500, 'PHP cURL extension is required.');
}

$requestUrl = $config['read_url'] . '?' . http_build_query(['api_token' => $config['read_token']]);
$curl = curl_init($requestUrl);

curl_setopt_array($curl, [
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_CONNECTTIMEOUT => 5,
    CURLOPT_TIMEOUT => 15,
    CURLOPT_HTTPHEADER => [
        'Accept: application/json',
    ],
    CURLOPT_SSL_VERIFYPEER => true,
    CURLOPT_SSL_VERIFYHOST => 2,
]);

$responseBody = curl_exec($curl);
$curlError = curl_errno($curl);
$statusCode = (int) curl_getinfo($curl, CURLINFO_HTTP_CODE);
curl_close($curl);

if ($responseBody === false || $curlError !== 0) {
    respondWithError(502, 'Could not connect to the cloud read API.');
}

$responseData = json_decode($responseBody);
if (json_last_error() !== JSON_ERROR_NONE || !is_object($responseData)) {
    respondWithError(502, 'Cloud read API returned invalid JSON.');
}

if ($statusCode < 200 || $statusCode >= 300) {
    http_response_code($statusCode >= 100 && $statusCode <= 599 ? $statusCode : 502);
    echo $responseBody;
    exit;
}

if (!isset($responseData->{$deviceId}) || !is_object($responseData->{$deviceId})) {
    respondWithError(403, 'This user does not have access to the requested device.');
}

$device = $responseData->{$deviceId};
$fileModified = $device->file_modified_unix ?? null;
if (is_int($fileModified) || (is_string($fileModified) && ctype_digit($fileModified))) {
    $fileModified = (int) $fileModified;
    header('Last-Modified: ' . gmdate('D, d M Y H:i:s', $fileModified));
    header('X-File-Modified-At: ' . gmdate('c', $fileModified));
    header('X-File-Modified-Unix: ' . $fileModified);
}

$state = $device->state ?? null;
if (!is_object($state)) {
    respondWithError(404, 'Device data not found.');
}

echo json_encode($state, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
