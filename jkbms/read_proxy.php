<?php
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

function respondWithError(int $statusCode, string $message): void {
    http_response_code($statusCode);
    echo json_encode(['error' => $message], JSON_UNESCAPED_UNICODE);
    exit;
}

function forwardHeaderIfPresent(array $sourceHeaders, string $name): void {
    $lookup = strtolower($name);
    foreach ($sourceHeaders as $key => $value) {
        if (strtolower((string) $key) === $lookup) {
            header($name . ': ' . $value, false);
            return;
        }
    }
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

$requestUrl = $config['read_url'] . '?' . http_build_query(['device' => $deviceId]);
$curl = curl_init($requestUrl);
$upstreamHeaders = [];

curl_setopt_array($curl, [
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_CONNECTTIMEOUT => 5,
    CURLOPT_TIMEOUT => 15,
    CURLOPT_HTTPHEADER => [
        'Authorization: Bearer ' . $config['read_token'],
        'Accept: application/json',
    ],
    CURLOPT_SSL_VERIFYPEER => true,
    CURLOPT_SSL_VERIFYHOST => 2,
    CURLOPT_HEADERFUNCTION => function ($curlHandle, $headerLine) use (&$upstreamHeaders) {
        $trimmed = trim($headerLine);
        if ($trimmed === '') {
            return strlen($headerLine);
        }

        if (preg_match('/^HTTP\//', $trimmed)) {
            return strlen($headerLine);
        }

        if (preg_match('/^([^:]+):\s*(.*)$/', $trimmed, $matches)) {
            $name = trim($matches[1]);
            $value = trim($matches[2]);
            $upstreamHeaders[strtolower($name)] = $value;
        }

        return strlen($headerLine);
    },
]);

$responseBody = curl_exec($curl);
$curlError = curl_errno($curl);
$statusCode = (int) curl_getinfo($curl, CURLINFO_HTTP_CODE);
curl_close($curl);

if ($responseBody === false || $curlError !== 0) {
    respondWithError(502, 'Could not connect to the cloud read API.');
}

foreach (['Last-Modified', 'X-File-Modified-At', 'X-File-Modified-Unix'] as $headerName) {
    if (isset($upstreamHeaders[strtolower($headerName)])) {
        header($headerName . ': ' . $upstreamHeaders[strtolower($headerName)], false);
    }
}

json_decode($responseBody);
if (json_last_error() !== JSON_ERROR_NONE) {
    respondWithError(502, 'Cloud read API returned invalid JSON.');
}

http_response_code($statusCode >= 100 && $statusCode <= 599 ? $statusCode : 502);
echo $responseBody;
