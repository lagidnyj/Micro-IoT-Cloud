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
header('Referrer-Policy: no-referrer');

function installEscape(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function installBase32Secret(): string
{
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $bits = '';
    foreach (unpack('C*', random_bytes(20)) as $byte) {
        $bits .= str_pad(decbin($byte), 8, '0', STR_PAD_LEFT);
    }

    $secret = '';
    foreach (str_split($bits, 5) as $chunk) {
        $secret .= $alphabet[bindec(str_pad($chunk, 5, '0'))];
    }

    return $secret;
}

function installWriteCheck(string $directory): void
{
    if (!is_dir($directory) || !is_writable($directory)) {
        throw new RuntimeException('Каталог недоступний для запису PHP: ' . $directory);
    }

    $testFile = $directory . DIRECTORY_SEPARATOR . '.install-check-' . bin2hex(random_bytes(8));
    $handle = @fopen($testFile, 'x');
    if ($handle === false) {
        throw new RuntimeException('Не вдалося створити перевірочний файл у каталозі: ' . $directory);
    }

    fclose($handle);
    if (!unlink($testFile)) {
        throw new RuntimeException('Не вдалося видалити перевірочний файл у каталозі: ' . $directory);
    }
}

function installSecureConnection(): bool
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

$projectDirectory = __DIR__;
$configDirectory = $projectDirectory . '/config';
$storageDirectory = $projectDirectory . '/storage';
$configPath = $configDirectory . '/config.php';
$databaseLockPath = $configDirectory . '/.installed';
$installKeyPath = $configDirectory . '/install.key';
$setupComplete = is_file($configPath) || is_file($databaseLockPath);

if (!isset($_SESSION['install_csrf'])) {
    $_SESSION['install_csrf'] = bin2hex(random_bytes(32));
}
$csrfToken = $_SESSION['install_csrf'];
$errorMessage = '';
$warningMessage = '';

if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
    $submittedCsrf = $_POST['csrf_token'] ?? '';
    if (!is_string($submittedCsrf) || !hash_equals($csrfToken, $submittedCsrf)) {
        http_response_code(400);
        exit('Invalid request token.');
    }

    $action = $_POST['action'] ?? '';
    if ($action === 'acknowledge_setup' && isset($_SESSION['install_totp'])) {
        unset($_SESSION['install_totp'], $_SESSION['install_username']);
        header('Location: install.php');
        exit;
    }

    if ($action === 'install') {
        $configCreated = false;
        $databaseCreated = false;
        $rulesCreated = false;
        $lockCreated = false;
        $databasePath = '';
        $pdo = null;

        try {
            if ($setupComplete) {
                throw new RuntimeException('Інсталяцію вже виконано. Видаліть install.php із сервера.');
            }
            if (!installSecureConnection()) {
                throw new RuntimeException('Відкрийте інсталятор через HTTPS. HTTP дозволено лише для localhost.');
            }
            if (is_link($installKeyPath) || !is_file($installKeyPath)) {
                throw new RuntimeException('Створіть файл config/install.key з одноразовим ключем, як описано вище.');
            }

            $storedKey = file_get_contents($installKeyPath);
            $submittedKey = $_POST['install_key'] ?? '';
            if ($storedKey === false
                || !is_string($submittedKey)
                || !preg_match('/\A[a-f0-9]{64}\z/i', trim($storedKey))
                || !hash_equals(trim($storedKey), trim($submittedKey))
            ) {
                throw new RuntimeException('Одноразовий ключ неправильний. Перевірте config/install.key.');
            }

            if (PHP_VERSION_ID < 70400 || !extension_loaded('pdo_sqlite') || !extension_loaded('json')) {
                throw new RuntimeException('Потрібні PHP 7.4 або новіший, PDO SQLite та JSON.');
            }

            $rootRulesPath = $projectDirectory . '/.htaccess';
            $storageRulesPath = $storageDirectory . '/.htaccess';
            $rootRules = is_file($rootRulesPath) ? file_get_contents($rootRulesPath) : false;
            if (!is_string($rootRules)
                || strpos($rootRules, 'RewriteRule ^storage(/|$) - [F,NC]') === false
                || strpos($rootRules, 'RewriteRule ^(sampleDB|config)(/|$) - [F,NC]') === false
                || !is_file($storageRulesPath)
            ) {
                throw new RuntimeException('Потрібні кореневий .htaccess із правилами блокування config/ і storage/ та storage/.htaccess.');
            }

            $username = trim(is_string($_POST['username'] ?? null) ? $_POST['username'] : '');
            $password = is_string($_POST['password'] ?? null) ? $_POST['password'] : '';
            $passwordConfirmation = is_string($_POST['password_confirmation'] ?? null)
                ? $_POST['password_confirmation']
                : '';
            $databaseFile = is_string($_POST['database_file'] ?? null)
                ? trim($_POST['database_file'])
                : '';

            if ($username === '' || strlen($username) > 64) {
                throw new RuntimeException('Логін має містити від 1 до 64 байтів.');
            }
            if (preg_match('/\A.{12,}\z/us', $password) !== 1) {
                throw new RuntimeException('Пароль має містити щонайменше 12 символів.');
            }
            if (strlen($password) > 72) {
                throw new RuntimeException('Пароль не має перевищувати 72 байти.');
            }
            if (!hash_equals($password, $passwordConfirmation)) {
                throw new RuntimeException('Паролі не збігаються.');
            }
            if (!preg_match('/\A[a-zA-Z0-9_-]{1,48}\.sqlite\z/', $databaseFile)) {
                throw new RuntimeException('Ім’я БД має містити лише латиницю, цифри, _ або - та завершуватися на .sqlite.');
            }

            installWriteCheck($configDirectory);
            installWriteCheck($storageDirectory);

            $databasePath = $configDirectory . '/' . $databaseFile;
            if (file_exists($databasePath) || is_link($databasePath)) {
                throw new RuntimeException('Файл БД уже існує. Виберіть нове ім’я, щоб не перезаписати дані.');
            }

            $rulesPath = $configDirectory . '/rules.json';
            if (file_exists($rulesPath)) {
                $rulesContents = is_file($rulesPath) ? file_get_contents($rulesPath) : false;
                $decodedRules = is_string($rulesContents) ? json_decode($rulesContents, true) : null;
                if (!is_array($decodedRules) || json_last_error() !== JSON_ERROR_NONE) {
                    throw new RuntimeException('config/rules.json уже існує, але містить некоректний JSON. Виправте файл перед інсталяцією.');
                }
            }

            $configContents = "<?php\n\ndeclare(strict_types=1);\n\nreturn [\n"
                . '    \'database_path\' => ' . var_export($databasePath, true) . ",\n];\n";
            $configHandle = @fopen($configPath, 'x');
            if ($configHandle === false) {
                throw new RuntimeException('Не вдалося створити config/config.php. Перевірте права або наявність файла.');
            }
            $configCreated = true;
            $writtenConfigBytes = fwrite($configHandle, $configContents);
            fclose($configHandle);
            if ($writtenConfigBytes !== strlen($configContents) || !chmod($configPath, 0640)) {
                throw new RuntimeException('Не вдалося повністю записати або захистити config/config.php.');
            }

            if (!file_exists($rulesPath)) {
                $rulesHandle = @fopen($rulesPath, 'x');
                if ($rulesHandle === false) {
                    throw new RuntimeException('Не вдалося створити config/rules.json.');
                }
                $rulesCreated = true;
                $writtenRulesBytes = fwrite($rulesHandle, "[]\n");
                fclose($rulesHandle);
                if ($writtenRulesBytes !== 3 || !chmod($rulesPath, 0640)) {
                    throw new RuntimeException('Не вдалося повністю створити config/rules.json.');
                }
            }

            $databaseCreated = true;
            require $projectDirectory . '/config/db.php';
            if (!chmod($databasePath, 0640)) {
                throw new RuntimeException('Не вдалося обмежити права доступу до SQLite-файла.');
            }

            $secret = installBase32Secret();
            $passwordHash = password_hash($password, PASSWORD_DEFAULT);
            if ($passwordHash === false) {
                throw new RuntimeException('Не вдалося захешувати пароль адміністратора.');
            }

            $pdo->beginTransaction();
            $statement = $pdo->prepare(
                'INSERT INTO users (username, password_hash, totp_secret, role) '
                . 'VALUES (:username, :password_hash, :totp_secret, :role)'
            );
            $statement->execute([
                ':username' => $username,
                ':password_hash' => $passwordHash,
                ':totp_secret' => $secret,
                ':role' => 'admin',
            ]);

            $lockHandle = @fopen($databaseLockPath, 'x');
            if ($lockHandle === false) {
                throw new RuntimeException('Не вдалося створити маркер завершення інсталяції.');
            }
            $lockCreated = true;
            $lockContents = gmdate(DateTime::ATOM) . "\n";
            $writtenLockBytes = fwrite($lockHandle, $lockContents);
            fclose($lockHandle);
            if ($writtenLockBytes !== strlen($lockContents) || !chmod($databaseLockPath, 0640)) {
                throw new RuntimeException('Не вдалося повністю записати маркер завершення інсталяції.');
            }

            $pdo->commit();
            $pdo = null;
            $setupComplete = true;
            $_SESSION['install_totp'] = [
                'secret' => $secret,
                'uri' => 'otpauth://totp/' . rawurlencode('Micro-IoT-Cloud:' . $username)
                    . '?' . http_build_query([
                        'secret' => $secret,
                        'issuer' => 'Micro-IoT-Cloud',
                        'algorithm' => 'SHA1',
                        'digits' => 6,
                        'period' => 30,
                    ]),
            ];
            $_SESSION['install_username'] = $username;

            if (!unlink($installKeyPath)) {
                $warningMessage = 'Інсталяція успішна, але файл config/install.key не вдалося видалити. Видаліть його вручну.';
            }
        } catch (Throwable $error) {
            if ($pdo instanceof PDO && $pdo->inTransaction()) {
                $pdo->rollBack();
            }
            $pdo = null;
            $cleanupFailures = [];

            if ($lockCreated && is_file($databaseLockPath) && !unlink($databaseLockPath)) {
                $cleanupFailures[] = $databaseLockPath;
            }
            $rulesPath = $configDirectory . '/rules.json';
            if ($rulesCreated && is_file($rulesPath) && !unlink($rulesPath)) {
                $cleanupFailures[] = $rulesPath;
            }
            if ($databaseCreated && $databasePath !== '') {
                foreach ([$databasePath, $databasePath . '-journal', $databasePath . '-wal', $databasePath . '-shm'] as $createdFile) {
                    if (is_file($createdFile) && !unlink($createdFile)) {
                        $cleanupFailures[] = $createdFile;
                    }
                }
            }
            if ($configCreated && is_file($configPath) && !unlink($configPath)) {
                $cleanupFailures[] = $configPath;
            }

            error_log('Cloud installer failed: ' . $error->getMessage());
            $errorMessage = $error instanceof RuntimeException
                ? $error->getMessage()
                : 'Не вдалося завершити інсталяцію. Перевірте PHP error log і права доступу.';
            if ($cleanupFailures !== []) {
                error_log('Cloud installer cleanup failed for: ' . implode(', ', $cleanupFailures));
                $errorMessage .= ' Не вдалося прибрати частину створених файлів; перевірте їх вручну: '
                    . implode(', ', $cleanupFailures) . '.';
            }
        }
    } else {
        http_response_code(400);
        $errorMessage = 'Невідома дія інсталятора.';
    }
}

$setupComplete = $setupComplete || is_file($configPath) || is_file($databaseLockPath);
$setupTotp = $_SESSION['install_totp'] ?? null;
$requirements = [
    ['PHP 7.4 або новіший', PHP_VERSION_ID >= 70400],
    ['PDO SQLite та JSON', extension_loaded('pdo_sqlite') && extension_loaded('json')],
    ['config/ доступна для запису', is_dir($configDirectory) && is_writable($configDirectory)],
    ['storage/ доступна для запису', is_dir($storageDirectory) && is_writable($storageDirectory)],
    ['кореневий .htaccess присутній', is_file($projectDirectory . '/.htaccess')],
    ['storage/.htaccess присутній', is_file($storageDirectory . '/.htaccess')],
    ['захищене HTTPS-з’єднання', installSecureConnection()],
];
?>
<!doctype html>
<html lang="uk">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Встановлення Micro-IoT-Cloud</title>
    <link rel="stylesheet" href="adminpanel/admin.css">
</head>
<body>
    <header class="top">
        <h1>Встановлення Micro-IoT-Cloud</h1>
    </header>

    <?php if ($errorMessage !== ''): ?>
        <div class="notice error"><?= installEscape($errorMessage) ?></div>
    <?php endif; ?>
    <?php if ($warningMessage !== ''): ?>
        <div class="notice error"><?= installEscape($warningMessage) ?></div>
    <?php endif; ?>

    <?php if (is_array($setupTotp)): ?>
        <section class="panel">
            <h2>Збережіть секрет 2FA для адміністратора <?= installEscape((string) ($_SESSION['install_username'] ?? '')) ?></h2>
            <p>Відскануйте QR-код застосунком-автентифікатором або введіть секрет вручну. Не закривайте цю сторінку, доки не збережете секрет.</p>
            <div id="totp-qr" class="totp-qr" data-otpauth="<?= installEscape((string) $setupTotp['uri']) ?>"></div>
            <p>Секрет 2FA: <code><?= installEscape((string) $setupTotp['secret']) ?></code></p>
            <p>Після налаштування увійдіть в <a href="adminpanel/admin.php">адмінку</a>. Тепер видаліть <code>install.php</code> із сервера.</p>
            <form method="post">
                <input type="hidden" name="csrf_token" value="<?= installEscape($csrfToken) ?>">
                <input type="hidden" name="action" value="acknowledge_setup">
                <button type="submit" class="primary">Секрет збережено</button>
            </form>
        </section>
        <script src="adminpanel/vendor/qrcode-generator.js"></script>
        <script>
            const qrElement = document.getElementById('totp-qr');
            if (typeof qrcode === 'function') {
                const qr = qrcode(0, 'M');
                qr.addData(qrElement.dataset.otpauth, 'Byte');
                qr.make();
                qrElement.innerHTML = qr.createSvgTag({ cellSize: 4, margin: 4, scalable: true });
            }
        </script>
    <?php elseif ($setupComplete): ?>
        <section class="panel">
            <h2>Хмару вже встановлено</h2>
            <p>Інсталятор більше не приймає налаштувань. Для безпеки видаліть <code>install.php</code> із сервера.</p>
            <p><a href="adminpanel/admin.php">Перейти до адмінки</a></p>
        </section>
    <?php else: ?>
        <section class="panel">
            <h2>Підготовка файлів</h2>
            <p>Завантажте в корінь сайту вміст <code>cloud-code/</code>: <code>index.html</code>, <code>.htaccess</code>, <code>install.php</code> та каталоги <code>adminpanel/</code>, <code>backend/</code>, <code>config/</code>, <code>storage/</code>.</p>
            <ul>
                <li>Не завантажуйте <code>sampleDB/</code>, <code>config.php</code>, <code>config.php.example</code>, README-файли або JSON-файли зі <code>storage/</code>.</li>
                <li>У <code>config/</code> завантажте лише <code>db.php</code> і <code>rules.json.example</code>. Файл <code>config.php</code> створить цей інсталятор.</li>
                <li>Збережіть кореневий <code>.htaccess</code> і <code>storage/.htaccess</code>: вони блокують прямий вебдоступ до конфігурації та сховища.</li>
            </ul>
            <p>Перед відкриттям сторінки створіть <code>config/install.key</code> із випадковим 64-символьним hex-ключем. Наприклад, згенеруйте його командою <code>openssl rand -hex 32</code>. Цей файл не додається до Git і буде видалений після успішного встановлення.</p>
        </section>

        <section class="panel">
            <h2>Перевірка сервера</h2>
            <ul>
                <?php foreach ($requirements as [$label, $passed]): ?>
                    <li><?= $passed ? '✓' : '✗' ?> <?= installEscape($label) ?></li>
                <?php endforeach; ?>
            </ul>
            <p class="muted">Права запису перевіряються ще раз перед створенням файлів. Налаштуйте PHP і Apache, якщо потрібні перевірки не пройдено.</p>
        </section>

        <section class="panel">
            <h2>Налаштування</h2>
            <form method="post" class="stack">
                <input type="hidden" name="csrf_token" value="<?= installEscape($csrfToken) ?>">
                <input type="hidden" name="action" value="install">
                <label>Одноразовий ключ з config/install.key
                    <input type="password" name="install_key" minlength="64" maxlength="64" pattern="[a-fA-F0-9]{64}" autocomplete="off" required>
                </label>
                <label>Ім’я SQLite-файла у захищеній теці config/
                    <input type="text" name="database_file" value="cloud.sqlite" pattern="[a-zA-Z0-9_-]{1,48}\.sqlite" maxlength="55" required>
                </label>
                <label>Логін першого адміністратора
                    <input type="text" name="username" maxlength="64" autocomplete="username" required>
                </label>
                <label>Пароль адміністратора (12–72 байти)
                    <input type="password" name="password" minlength="12" maxlength="72" autocomplete="new-password" required>
                </label>
                <label>Повторіть пароль
                    <input type="password" name="password_confirmation" minlength="12" maxlength="72" autocomplete="new-password" required>
                </label>
                <button type="submit" class="primary">Створити БД і адміністратора</button>
            </form>
        </section>
    <?php endif; ?>
</body>
</html>
