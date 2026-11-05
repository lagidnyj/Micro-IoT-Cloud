<?php
declare(strict_types=1);

function deviceHistoryPresets(): array
{
    return [
        'off' => [
            'label' => 'Без історії',
            'enabled' => 0,
            'interval_seconds' => 3600,
            'retention_seconds' => 604800,
        ],
        'hourly_7d' => [
            'label' => '1 година · 7 днів',
            'enabled' => 1,
            'interval_seconds' => 3600,
            'retention_seconds' => 604800,
        ],
        'half_hourly_3d' => [
            'label' => '30 хвилин · 3 дні',
            'enabled' => 1,
            'interval_seconds' => 1800,
            'retention_seconds' => 259200,
        ],
    ];
}

function deviceHistoryPresetKey(array $settings): string
{
    foreach (deviceHistoryPresets() as $key => $preset) {
        if ((int) $settings['enabled'] === $preset['enabled']
            && (int) $settings['interval_seconds'] === $preset['interval_seconds']
            && (int) $settings['retention_seconds'] === $preset['retention_seconds']
        ) {
            return $key;
        }
    }

    return 'off';
}

function deviceHistoryLabel(array $settings): string
{
    if ((int) $settings['enabled'] !== 1) {
        return 'Вимкнена';
    }

    foreach (deviceHistoryPresets() as $key => $preset) {
        if ($key !== 'off'
            && (int) $settings['interval_seconds'] === $preset['interval_seconds']
            && (int) $settings['retention_seconds'] === $preset['retention_seconds']
        ) {
            return $preset['label'];
        }
    }

    $interval = (int) $settings['interval_seconds'];
    $retention = (int) $settings['retention_seconds'];
    $intervalLabel = $interval === 1800
        ? '30 хвилин'
        : ($interval === 3600 ? '1 година' : $interval . ' с');
    $retentionLabel = $retention % 86400 === 0
        ? (int) ($retention / 86400) . ' днів'
        : ($retention % 3600 === 0
            ? (int) ($retention / 3600) . ' год'
            : $retention . ' с');

    return $intervalLabel . ' · ' . $retentionLabel;
}

function deviceHistoryPath(string $storageDirectory, string $deviceId): string
{
    if (!preg_match('/\A[a-zA-Z0-9_-]{1,64}\z/', $deviceId)) {
        throw new InvalidArgumentException('Invalid device ID for history.');
    }

    return rtrim($storageDirectory, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $deviceId . '.ndjson';
}

function acquireDeviceHistoryLock(string $storageDirectory)
{
    if (!is_dir($storageDirectory)) {
        throw new RuntimeException('Device storage directory does not exist.');
    }

    $lockPath = rtrim($storageDirectory, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . '.history.lock';
    $handle = fopen($lockPath, 'c');
    if ($handle === false) {
        throw new RuntimeException('Could not open device history lock.');
    }
    if (!flock($handle, LOCK_EX)) {
        fclose($handle);
        throw new RuntimeException('Could not lock device history storage.');
    }

    return $handle;
}

function releaseDeviceHistoryLock($handle): void
{
    flock($handle, LOCK_UN);
    fclose($handle);
}

function readDeviceHistoryRecords(string $path): array
{
    if (is_link($path)) {
        throw new RuntimeException('Device history path must not be a symbolic link.');
    }
    if (!is_file($path)) {
        return [];
    }

    $contents = file_get_contents($path);
    if ($contents === false) {
        throw new RuntimeException('Could not read device history file.');
    }
    if ($contents === '') {
        return [];
    }

    $lines = explode("\n", rtrim($contents, "\r\n"));
    $records = [];
    foreach ($lines as $line) {
        $record = json_decode($line);
        if (json_last_error() !== JSON_ERROR_NONE
            || !is_object($record)
            || !isset($record->timestamp, $record->slot, $record->interval_seconds, $record->state)
            || !is_string($record->timestamp)
            || !is_string($record->slot)
            || !is_int($record->interval_seconds)
            || $record->interval_seconds < 1
            || !is_object($record->state)
            || !deviceHistoryTimestamp($record->timestamp)
            || !deviceHistoryTimestamp($record->slot)
        ) {
            throw new RuntimeException('Device history contains an invalid NDJSON record.');
        }
        $records[] = $record;
    }

    return $records;
}

function deviceHistoryTimestamp(string $value): ?int
{
    $date = DateTimeImmutable::createFromFormat('!Y-m-d\TH:i:s\Z', $value, new DateTimeZone('UTC'));
    $errors = DateTimeImmutable::getLastErrors();
    if ($date === false
        || ($errors !== false && ($errors['warning_count'] > 0 || $errors['error_count'] > 0))
        || $date->format('Y-m-d\TH:i:s\Z') !== $value
    ) {
        return null;
    }

    return $date->getTimestamp();
}

function writeDeviceHistoryRecords(string $path, array $records): void
{
    if (!$records) {
        if (is_link($path)) {
            throw new RuntimeException('Device history path must not be a symbolic link.');
        }
        if (is_file($path) && !unlink($path)) {
            throw new RuntimeException('Could not remove expired device history file.');
        }
        return;
    }

    if (is_link($path)) {
        throw new RuntimeException('Device history path must not be a symbolic link.');
    }

    $directory = dirname($path);
    $temporaryPath = tempnam($directory, '.history-');
    if ($temporaryPath === false || realpath(dirname($temporaryPath)) !== realpath($directory)) {
        if (is_string($temporaryPath) && is_file($temporaryPath)) {
            unlink($temporaryPath);
        }
        throw new RuntimeException('Could not create temporary device history file.');
    }

    $contents = '';
    foreach ($records as $record) {
        $line = json_encode($record, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        if ($line === false) {
            unlink($temporaryPath);
            throw new RuntimeException('Could not encode device history record.');
        }
        $contents .= $line . "\n";
    }

    $bytesWritten = file_put_contents($temporaryPath, $contents, LOCK_EX);
    if ($bytesWritten !== strlen($contents) || !chmod($temporaryPath, 0640)) {
        unlink($temporaryPath);
        throw new RuntimeException('Could not write temporary device history file.');
    }
    if (!rename($temporaryPath, $path)) {
        unlink($temporaryPath);
        throw new RuntimeException('Could not replace device history file.');
    }
}

function recordDeviceHistory(
    string $storageDirectory,
    string $deviceId,
    string $payload,
    int $receivedAt,
    int $intervalSeconds,
    int $retentionSeconds
): void {
    if ($intervalSeconds < 1 || $retentionSeconds < 1) {
        throw new InvalidArgumentException('History interval and retention must be positive.');
    }

    $path = deviceHistoryPath($storageDirectory, $deviceId);
    $lock = acquireDeviceHistoryLock($storageDirectory);
    try {
        $records = readDeviceHistoryRecords($path);
        $cutoff = $receivedAt - $retentionSeconds;
        $retainedRecords = array_values(array_filter(
            $records,
            static function ($record) use ($cutoff): bool {
                return deviceHistoryTimestamp($record->timestamp) >= $cutoff;
            }
        ));
        if (count($retainedRecords) !== count($records)) {
            writeDeviceHistoryRecords($path, $retainedRecords);
        }

        $slotTimestamp = intdiv($receivedAt, $intervalSeconds) * $intervalSeconds;
        $slot = gmdate('Y-m-d\TH:i:s\Z', $slotTimestamp);
        foreach ($retainedRecords as $record) {
            if ($record->interval_seconds === $intervalSeconds && $record->slot === $slot) {
                return;
            }
        }

        $state = json_decode($payload);
        if (json_last_error() !== JSON_ERROR_NONE || !is_object($state)) {
            throw new RuntimeException('Device payload is invalid JSON while recording history.');
        }

        $record = (object) [
            'timestamp' => gmdate('Y-m-d\TH:i:s\Z', $receivedAt),
            'slot' => $slot,
            'interval_seconds' => $intervalSeconds,
            'state' => $state,
        ];
        $line = json_encode($record, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        if ($line === false) {
            throw new RuntimeException('Could not encode device history record.');
        }

        if (!$retainedRecords && !is_file($path)) {
            writeDeviceHistoryRecords($path, [$record]);
            return;
        }

        $handle = fopen($path, 'c+b');
        if ($handle === false) {
            throw new RuntimeException('Could not open device history file for writing.');
        }
        if (fseek($handle, 0, SEEK_END) !== 0) {
            fclose($handle);
            throw new RuntimeException('Could not seek to the end of device history file.');
        }
        $originalSize = ftell($handle);
        if ($originalSize === false) {
            fclose($handle);
            throw new RuntimeException('Could not determine device history file size.');
        }

        $line .= "\n";
        $written = 0;
        while ($written < strlen($line)) {
            $bytes = fwrite($handle, substr($line, $written));
            if ($bytes === false || $bytes === 0) {
                $restored = ftruncate($handle, $originalSize) && fflush($handle);
                fclose($handle);
                if (!$restored) {
                    throw new RuntimeException('Device history append failed and its partial write could not be removed.');
                }
                throw new RuntimeException('Could not append device history record.');
            }
            $written += $bytes;
        }
        if (!fflush($handle)) {
            $restored = ftruncate($handle, $originalSize) && fflush($handle);
            fclose($handle);
            if (!$restored) {
                throw new RuntimeException('Device history flush failed and its partial write could not be removed.');
            }
            throw new RuntimeException('Could not flush device history file.');
        }
        fclose($handle);
    } finally {
        releaseDeviceHistoryLock($lock);
    }
}

function deleteDeviceHistory(string $storageDirectory, string $deviceId): void
{
    $path = deviceHistoryPath($storageDirectory, $deviceId);
    $lock = acquireDeviceHistoryLock($storageDirectory);
    try {
        if (is_link($path)) {
            throw new RuntimeException('Device history path must not be a symbolic link.');
        }
        if (is_file($path) && !unlink($path)) {
            throw new RuntimeException('Could not delete device history file.');
        }
    } finally {
        releaseDeviceHistoryLock($lock);
    }
}

function readRetainedDeviceHistory(
    string $storageDirectory,
    string $deviceId,
    int $retentionSeconds,
    int $now
): string {
    if ($retentionSeconds < 1) {
        throw new InvalidArgumentException('History retention must be positive.');
    }

    $path = deviceHistoryPath($storageDirectory, $deviceId);
    $lock = acquireDeviceHistoryLock($storageDirectory);
    try {
        $records = readDeviceHistoryRecords($path);
        $cutoff = $now - $retentionSeconds;
        $retainedRecords = array_values(array_filter(
            $records,
            static function ($record) use ($cutoff): bool {
                return deviceHistoryTimestamp($record->timestamp) >= $cutoff;
            }
        ));
        if (count($retainedRecords) !== count($records)) {
            writeDeviceHistoryRecords($path, $retainedRecords);
        }

        $contents = '';
        foreach ($retainedRecords as $record) {
            $line = json_encode($record, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
            if ($line === false) {
                throw new RuntimeException('Could not encode device history response.');
            }
            $contents .= $line . "\n";
        }

        return $contents;
    } finally {
        releaseDeviceHistoryLock($lock);
    }
}
