<?php
declare(strict_types=1);

ini_set('session.use_strict_mode', '1');
session_set_cookie_params([
    'httponly' => true,
    'secure' => !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
    'samesite' => 'Strict',
]);
session_start();

header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: no-referrer');

require_once __DIR__ . '/../includes/totp.php';

function recoveryEscape(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function recoverySecureConnection(): bool
{
    $https = strtolower((string) ($_SERVER['HTTPS'] ?? ''));
    if ($https !== '' && $https !== 'off' && $https !== '0') {
        return true;
    }

    $host = strtolower((string) parse_url(
        'http://' . (string) ($_SERVER['HTTP_HOST'] ?? ''),
        PHP_URL_HOST
    ));
    return in_array($host, ['localhost', '127.0.0.1', '[::1]', '::1'], true);
}

function recoveryReadKey(string $path): string
{
    if (is_link($path) || !is_file($path)) {
        throw new RuntimeException('Файл config/recovery.key відсутній або некоректний.');
    }

    $contents = @file_get_contents($path);
    if (!is_string($contents)) {
        throw new RuntimeException('Не вдалося прочитати config/recovery.key.');
    }
    $key = trim($contents);
    if (!preg_match('/\A[a-fA-F0-9]{64}\z/', $key)) {
        throw new RuntimeException('Файл config/recovery.key має містити 64 hex-символи.');
    }

    return $key;
}

function recoveryRedirect(): void
{
    header('Location: ' . (string) ($_SERVER['SCRIPT_NAME'] ?? 'reset.php'));
    exit;
}

$projectDirectory = dirname(__DIR__);
$configDirectory = $projectDirectory . '/config';
$keyPath = $configDirectory . '/recovery.key';

if (!recoverySecureConnection()) {
    http_response_code(403);
    exit('Відкрийте сторінку відновлення через HTTPS. HTTP дозволено лише для localhost.');
}

if (!isset($_SESSION['recovery_csrf'])) {
    $_SESSION['recovery_csrf'] = bin2hex(random_bytes(32));
}
$csrfToken = $_SESSION['recovery_csrf'];
$errorMessage = is_string($_SESSION['recovery_error'] ?? null)
    ? $_SESSION['recovery_error']
    : '';
unset($_SESSION['recovery_error']);

$pending = $_SESSION['recovery_pending'] ?? null;
if (is_array($pending)
    && (!isset($pending['started_at']) || time() - (int) $pending['started_at'] > 600)
) {
    unset($_SESSION['recovery_pending']);
    $pending = null;
    $errorMessage = 'Час відновлення вичерпано. Почніть процедуру спочатку.';
}

if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
    $submittedCsrf = $_POST['csrf_token'] ?? '';
    if (!is_string($submittedCsrf) || !hash_equals($csrfToken, $submittedCsrf)) {
        http_response_code(400);
        exit('Invalid request token.');
    }

    $action = $_POST['action'] ?? '';
    try {
        if ($action === 'begin') {
            $storedKey = recoveryReadKey($keyPath);
            $submittedKey = $_POST['recovery_key'] ?? '';
            if (!is_string($submittedKey) || !hash_equals($storedKey, $submittedKey)) {
                throw new InvalidArgumentException('Ключ відновлення неправильний.');
            }

            $username = trim(is_string($_POST['username'] ?? null) ? $_POST['username'] : '');
            $password = is_string($_POST['password'] ?? null) ? $_POST['password'] : '';
            $passwordConfirmation = is_string($_POST['password_confirmation'] ?? null)
                ? $_POST['password_confirmation']
                : '';
            if ($username === '' || strlen($username) > 64) {
                throw new InvalidArgumentException('Логін має містити від 1 до 64 байтів.');
            }
            if (preg_match('/\A.{12,}\z/us', $password) !== 1 || strlen($password) > 72) {
                throw new InvalidArgumentException('Пароль має містити щонайменше 12 символів і не більше 72 байтів.');
            }
            if (!hash_equals($password, $passwordConfirmation)) {
                throw new InvalidArgumentException('Паролі не збігаються.');
            }

            $configPath = $configDirectory . '/config.php';
            if (is_link($configPath) || !is_file($configPath)) {
                throw new RuntimeException('Серверну конфігурацію не знайдено.');
            }
            $databaseConfig = require $configPath;
            $databasePath = $databaseConfig['database_path'] ?? null;
            if (!is_string($databasePath) || !is_file($databasePath) || is_link($databasePath)) {
                throw new RuntimeException('Наявну базу даних не знайдено.');
            }
            require $configDirectory . '/db.php';

            $statement = $pdo->prepare(
                "SELECT id FROM users WHERE username = :username AND role = 'admin'"
            );
            $statement->execute([':username' => $username]);
            $userId = $statement->fetchColumn();
            if ($userId === false) {
                throw new InvalidArgumentException('Не вдалося знайти обліковий запис адміністратора.');
            }

            $passwordHash = password_hash($password, PASSWORD_DEFAULT);
            if ($passwordHash === false) {
                throw new RuntimeException('Не вдалося захешувати пароль.');
            }

            session_regenerate_id(true);
            $_SESSION['recovery_csrf'] = bin2hex(random_bytes(32));
            $_SESSION['recovery_pending'] = [
                'user_id' => (int) $userId,
                'username' => $username,
                'password_hash' => $passwordHash,
                'totp_secret' => createTotpSecret(),
                'key_fingerprint' => hash('sha256', $storedKey),
                'started_at' => time(),
                'attempts' => 0,
            ];
            recoveryRedirect();
        }

        if ($action === 'verify_totp') {
            $pending = $_SESSION['recovery_pending'] ?? null;
            if (!is_array($pending) || time() - (int) ($pending['started_at'] ?? 0) > 600) {
                unset($_SESSION['recovery_pending']);
                throw new InvalidArgumentException('Час відновлення вичерпано. Почніть процедуру спочатку.');
            }

            $code = $_POST['totp_code'] ?? '';
            if (!is_string($code)
                || !verifyTotpCode((string) $pending['totp_secret'], $code, time())
            ) {
                $attempts = (int) ($pending['attempts'] ?? 0) + 1;
                if ($attempts >= 5) {
                    unset($_SESSION['recovery_pending']);
                    throw new InvalidArgumentException('Забагато неправильних кодів. Почніть процедуру спочатку.');
                }
                $_SESSION['recovery_pending']['attempts'] = $attempts;
                throw new InvalidArgumentException('Код 2FA неправильний. Перевірте час на телефоні й спробуйте ще раз.');
            }

            $databaseConfig = require $configDirectory . '/config.php';
            $databasePath = $databaseConfig['database_path'] ?? null;
            if (!is_string($databasePath) || !is_file($databasePath) || is_link($databasePath)) {
                throw new RuntimeException('Наявну базу даних не знайдено.');
            }
            require $configDirectory . '/db.php';

            $keyHandle = @fopen($keyPath, 'r');
            if ($keyHandle === false || !flock($keyHandle, LOCK_EX)) {
                if (is_resource($keyHandle)) {
                    fclose($keyHandle);
                }
                throw new RuntimeException('Не вдалося заблокувати ключ відновлення.');
            }

            $keyRemoved = false;
            $databaseCommitted = false;
            $storedKey = '';
            try {
                $storedKey = recoveryReadKey($keyPath);
                if (!hash_equals((string) $pending['key_fingerprint'], hash('sha256', $storedKey))) {
                    throw new RuntimeException('Ключ відновлення вже використано або замінено.');
                }

                $pdo->beginTransaction();
                $statement = $pdo->prepare(
                    "UPDATE users SET password_hash = :password_hash, totp_secret = :totp_secret "
                    . "WHERE id = :id AND role = 'admin'"
                );
                $statement->execute([
                    ':password_hash' => $pending['password_hash'],
                    ':totp_secret' => $pending['totp_secret'],
                    ':id' => (int) $pending['user_id'],
                ]);
                if ($statement->rowCount() !== 1) {
                    throw new RuntimeException('Обліковий запис адміністратора змінився.');
                }

                if (!unlink($keyPath)) {
                    throw new RuntimeException('Не вдалося видалити ключ відновлення.');
                }
                $keyRemoved = true;
                if (!$pdo->commit()) {
                    throw new RuntimeException('Не вдалося зберегти зміни.');
                }
                $databaseCommitted = true;
            } catch (Throwable $exception) {
                if ($pdo->inTransaction()) {
                    $pdo->rollBack();
                }
                if ($keyRemoved && !$databaseCommitted && !file_exists($keyPath)) {
                    $restoreHandle = @fopen($keyPath, 'x');
                    if ($restoreHandle === false
                        || fwrite($restoreHandle, $storedKey . "\n") !== strlen($storedKey) + 1
                    ) {
                        error_log('Could not restore recovery key after a failed password reset.');
                    }
                    if (is_resource($restoreHandle)) {
                        fclose($restoreHandle);
                        @chmod($keyPath, 0600);
                    }
                }
                throw $exception;
            } finally {
                flock($keyHandle, LOCK_UN);
                fclose($keyHandle);
            }

            session_regenerate_id(true);
            unset($_SESSION['recovery_pending']);
            $_SESSION['recovery_csrf'] = bin2hex(random_bytes(32));
            $_SESSION['recovery_complete'] = true;
            recoveryRedirect();
        }

        throw new InvalidArgumentException('Некоректна дія.');
    } catch (InvalidArgumentException $exception) {
        $_SESSION['recovery_error'] = $exception->getMessage();
        recoveryRedirect();
    } catch (Throwable $exception) {
        error_log('Emergency admin recovery failed: ' . $exception->getMessage());
        $_SESSION['recovery_error'] = 'Відновлення не завершено. Перевірте конфігурацію та журнал помилок сервера.';
        recoveryRedirect();
    }
}

$pending = $_SESSION['recovery_pending'] ?? null;
$recoveryComplete = !empty($_SESSION['recovery_complete']);
$totpUri = '';
if (is_array($pending)) {
    $totpUri = 'otpauth://totp/' . rawurlencode('Micro-IoT-Cloud:' . $pending['username'])
        . '?' . http_build_query([
            'secret' => $pending['totp_secret'],
            'issuer' => 'Micro-IoT-Cloud',
            'algorithm' => 'SHA1',
            'digits' => 6,
            'period' => 30,
        ]);
}
?>
<!doctype html>
<html lang="uk">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Аварійне відновлення адмінки</title>
    <style>
        body { font: 16px/1.5 system-ui, sans-serif; max-width: 720px; margin: 2rem auto; padding: 0 1rem; color: #17212b; }
        main { border: 1px solid #ccd4dc; border-radius: 8px; padding: 1.5rem; }
        label { display: block; margin: 1rem 0 .25rem; font-weight: 600; }
        input { box-sizing: border-box; width: 100%; padding: .65rem; }
        button { margin-top: 1rem; padding: .7rem 1rem; cursor: pointer; }
        .error { color: #9b1c1c; }
        .notice { background: #f2f6fa; padding: .75rem; overflow-wrap: anywhere; }
        .totp-qr { max-width: 260px; }
        .totp-qr svg { width: 100%; height: auto; }
    </style>
</head>
<body>
<main>
    <h1>Аварійне відновлення адмінки</h1>
    <?php if ($errorMessage !== ''): ?>
        <p class="error" role="alert"><?= recoveryEscape($errorMessage) ?></p>
    <?php endif; ?>

    <?php if ($recoveryComplete): ?>
        <p>Пароль і 2FA адміністратора оновлено. Усі попередні сесії адмінки завершаться.</p>
        <p><strong>Терміново видаліть цей файл із сервера</strong> та перевірте, що <code>config/recovery.key</code> відсутній.</p>
    <?php elseif (is_array($pending)): ?>
        <p>Відскануйте QR-код застосунком-автентифікатором. Новий пароль і секрет 2FA буде збережено лише після перевірки коду.</p>
        <div class="totp-qr" data-otpauth="<?= recoveryEscape($totpUri) ?>"></div>
        <p class="notice">Якщо QR-код недоступний, введіть секрет вручну: <code><?= recoveryEscape($pending['totp_secret']) ?></code></p>
        <form method="post">
            <input type="hidden" name="csrf_token" value="<?= recoveryEscape($csrfToken) ?>">
            <input type="hidden" name="action" value="verify_totp">
            <label for="totp_code">Код із застосунку (6 цифр)</label>
            <input id="totp_code" name="totp_code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code" required autofocus>
            <button type="submit">Підтвердити 2FA та зберегти доступ</button>
        </form>
    <?php else: ?>
        <p>Процедура замінить пароль і секрет 2FA вибраного адміністратора. База та інші дані не змінюються.</p>
        <form method="post">
            <input type="hidden" name="csrf_token" value="<?= recoveryEscape($csrfToken) ?>">
            <input type="hidden" name="action" value="begin">
            <label for="username">Логін адміністратора</label>
            <input id="username" name="username" maxlength="64" autocomplete="username" required>
            <label for="password">Новий пароль (від 12 символів)</label>
            <input id="password" type="password" name="password" minlength="12" maxlength="72" autocomplete="new-password" required>
            <label for="password_confirmation">Повторіть новий пароль</label>
            <input id="password_confirmation" type="password" name="password_confirmation" minlength="12" maxlength="72" autocomplete="new-password" required>
            <label for="recovery_key">Одноразовий ключ відновлення</label>
            <input id="recovery_key" type="password" name="recovery_key" minlength="64" maxlength="64" pattern="[a-fA-F0-9]{64}" autocomplete="off" required>
            <button type="submit">Перейти до налаштування 2FA</button>
        </form>
    <?php endif; ?>
</main>
<?php if (is_array($pending) && !$recoveryComplete): ?>
    <script src="../adminpanel/vendor/qrcode-generator.js"></script>
    <script>
        document.querySelectorAll('.totp-qr[data-otpauth]').forEach((element) => {
            const qr = qrcode(0, 'M');
            qr.addData(element.dataset.otpauth, 'Byte');
            qr.make();
            element.innerHTML = qr.createSvgTag({ cellSize: 4, margin: 4, scalable: true });
        });
    </script>
<?php endif; ?>
</body>
</html>
