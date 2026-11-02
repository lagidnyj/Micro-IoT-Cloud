<?php
declare(strict_types=1);

function base32Encode(string $value): string
{
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $bits = '';
    foreach (unpack('C*', $value) as $byte) {
        $bits .= str_pad(decbin($byte), 8, '0', STR_PAD_LEFT);
    }

    $encoded = '';
    foreach (str_split($bits, 5) as $chunk) {
        $encoded .= $alphabet[bindec(str_pad($chunk, 5, '0'))];
    }

    return $encoded;
}

function createTotpSecret(): string
{
    return base32Encode(random_bytes(20));
}

function verifyTotpCode(string $secret, string $code, int $timestamp): bool
{
    if (!preg_match('/\A[0-9]{6}\z/', $code) || !preg_match('/\A[A-Z2-7]+\z/', $secret)) {
        return false;
    }

    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $bits = '';
    foreach (str_split($secret) as $character) {
        $value = strpos($alphabet, $character);
        if ($value === false) {
            return false;
        }
        $bits .= str_pad(decbin($value), 5, '0', STR_PAD_LEFT);
    }

    $key = '';
    foreach (str_split($bits, 8) as $byte) {
        if (strlen($byte) === 8) {
            $key .= chr(bindec($byte));
        }
    }
    if ($key === '') {
        return false;
    }

    $counter = (int) floor($timestamp / 30);
    for ($offset = -1; $offset <= 1; $offset++) {
        $timeCounter = $counter + $offset;
        $message = pack('N2', ($timeCounter >> 32) & 0xffffffff, $timeCounter & 0xffffffff);
        $hash = hash_hmac('sha1', $message, $key, true);
        $position = ord($hash[19]) & 0x0f;
        $binary = ((ord($hash[$position]) & 0x7f) << 24)
            | ((ord($hash[$position + 1]) & 0xff) << 16)
            | ((ord($hash[$position + 2]) & 0xff) << 8)
            | (ord($hash[$position + 3]) & 0xff);
        $expectedCode = str_pad((string) ($binary % 1000000), 6, '0', STR_PAD_LEFT);
        if (hash_equals($expectedCode, $code)) {
            return true;
        }
    }

    return false;
}
