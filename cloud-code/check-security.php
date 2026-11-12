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

$adminUrl = 'adminpanel/admin.php';
$now = time();
$adminUserId = (int) ($_SESSION['admin_user_id'] ?? 0);
$lastActivity = (int) ($_SESSION['admin_last_activity'] ?? 0);

if ($adminUserId <= 0 || $lastActivity <= 0 || $now - $lastActivity > 1800) {
    unset($_SESSION['admin_user_id'], $_SESSION['admin_last_activity'], $_SESSION['admin_password_hash']);
    header('Location: ' . $adminUrl, true, 303);
    exit;
}

$configPath = __DIR__ . '/config/config.php';
if (!is_file($configPath)) {
    http_response_code(503);
    exit('Перевірка недоступна: конфігурацію бази даних не знайдено.');
}

try {
    $config = require $configPath;
    $databasePath = is_array($config) ? ($config['database_path'] ?? null) : null;
    if (!is_string($databasePath) || $databasePath === '' || !is_file($databasePath)) {
        throw new RuntimeException('Invalid or missing database path.');
    }

    $pdo = new PDO('sqlite:' . $databasePath);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->exec('PRAGMA query_only = ON');
    $statement = $pdo->prepare("SELECT password_hash FROM users WHERE id = :id AND role = 'admin'");
    $statement->execute([':id' => $adminUserId]);
    $authenticatedUser = $statement->fetch(PDO::FETCH_ASSOC);
} catch (Throwable $error) {
    error_log('Security check could not validate the admin session: ' . $error->getMessage());
    http_response_code(503);
    exit('Перевірка недоступна: не вдалося перевірити адміністративну сесію.');
}

if (!$authenticatedUser
    || !isset($_SESSION['admin_password_hash'])
    || !is_string($_SESSION['admin_password_hash'])
    || !is_string($authenticatedUser['password_hash'])
    || !hash_equals($authenticatedUser['password_hash'], $_SESSION['admin_password_hash'])
) {
    unset($_SESSION['admin_user_id'], $_SESSION['admin_last_activity'], $_SESSION['admin_password_hash']);
    session_regenerate_id(true);
    header('Location: ' . $adminUrl, true, 303);
    exit;
}

$_SESSION['admin_last_activity'] = $now;

function checkSecurityAppUrl(string $path, bool $documentRootRelative = false): string
{
    if ($documentRootRelative) {
        return '/' . ltrim($path, '/');
    }

    $scriptDirectory = str_replace('\\', '/', dirname((string) ($_SERVER['SCRIPT_NAME'] ?? '/check-security.php')));
    $basePath = $scriptDirectory === '/' || $scriptDirectory === '.' ? '' : rtrim($scriptDirectory, '/');

    return $basePath . '/' . ltrim($path, '/');
}

$targets = [
    ['label' => 'Каталог storage/', 'path' => 'storage/', 'type' => 'directory'],
    ['label' => 'config/config.php', 'path' => 'config/config.php', 'type' => 'php'],
    ['label' => 'config/db.php', 'path' => 'config/db.php', 'type' => 'php'],
    ['label' => 'config/rules.json', 'path' => 'config/rules.json', 'type' => 'file'],
    ['label' => 'config/states.json', 'path' => 'config/states.json', 'type' => 'file'],
    ['label' => 'sampleDB/database.sqlite', 'path' => 'sampleDB/database.sqlite', 'type' => 'file'],
    ['label' => '.env', 'path' => '.env', 'type' => 'file'],
    ['label' => '.git/HEAD', 'path' => '.git/HEAD', 'type' => 'file'],
    ['label' => '.htaccess', 'path' => '.htaccess', 'type' => 'file'],
];

$storageDirectory = __DIR__ . '/storage';
$storageIsSymlink = is_link($storageDirectory);
foreach (['json', 'ndjson'] as $extension) {
    $label = $extension === 'json' ? 'Приклад JSON зі storage/' : 'Приклад NDJSON-історії зі storage/';
    $filePath = null;
    $storageRealPath = realpath($storageDirectory);

    if (!$storageIsSymlink && $storageRealPath !== false) {
        $files = glob($storageDirectory . '/*.' . $extension, GLOB_NOSORT);
        if (is_array($files)) {
            foreach ($files as $candidate) {
                $candidateRealPath = realpath($candidate);
                if (is_file($candidate)
                    && !is_link($candidate)
                    && $candidateRealPath !== false
                    && dirname($candidateRealPath) === $storageRealPath
                ) {
                    $filePath = 'storage/' . rawurlencode(basename($candidate));
                    break;
                }
            }
        }
    }

    $targets[] = [
        'label' => $label,
        'path' => $filePath,
        'type' => 'file',
    ];
}

$databaseRealPath = realpath($databasePath);
$projectRoot = realpath(__DIR__);
$documentRoot = realpath((string) ($_SERVER['DOCUMENT_ROOT'] ?? ''));
$databaseUrlPath = null;
$databaseUrlIsDocumentRootRelative = false;
$databaseMissingLabel = 'Не вдалося визначити URL БД; перевірте її розташування та серверні alias';
if ($databaseRealPath !== false && $projectRoot !== false) {
    $projectRootPrefix = rtrim($projectRoot, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
    if (strncmp($databaseRealPath, $projectRootPrefix, strlen($projectRootPrefix)) === 0) {
        $relativeDatabasePath = substr($databaseRealPath, strlen($projectRootPrefix));
        $databaseParts = explode(DIRECTORY_SEPARATOR, $relativeDatabasePath);
        $databaseUrlPath = implode('/', array_map('rawurlencode', $databaseParts));
    }
}
if ($databaseUrlPath === null && $databaseRealPath !== false && $documentRoot !== false) {
    $documentRootPrefix = rtrim($documentRoot, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
    if (strncmp($databaseRealPath, $documentRootPrefix, strlen($documentRootPrefix)) === 0) {
        $relativeDatabasePath = substr($databaseRealPath, strlen($documentRootPrefix));
        $databaseParts = explode(DIRECTORY_SEPARATOR, $relativeDatabasePath);
        $databaseUrlPath = implode('/', array_map('rawurlencode', $databaseParts));
        $databaseUrlIsDocumentRootRelative = true;
    } elseif ($databaseRealPath === $documentRoot) {
        $databaseMissingLabel = 'Шлях БД збігається з web root; перевірте конфігурацію вручну';
    } else {
        $databaseMissingLabel = 'БД поза web root; перевірте також налаштування серверних alias';
    }
}

$targets[] = [
    'label' => 'Файл SQLite-БД',
    'path' => $databaseUrlPath,
    'type' => 'file',
    'documentRootRelative' => $databaseUrlIsDocumentRootRelative,
    'missingLabel' => $databaseMissingLabel,
];

?>
<!doctype html>
<html lang="uk">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Перевірка доступу до файлів</title>
    <style>
        :root { color-scheme: dark; font: 16px/1.5 system-ui, sans-serif; background: #10141b; color: #e8edf5; }
        body { max-width: 54rem; margin: 3rem auto; padding: 0 1rem; }
        h1 { font-size: 1.6rem; }
        p { color: #aab6c7; }
        button { padding: .65rem 1rem; color: #fff; background: #245caa; border: 0; border-radius: .4rem; cursor: pointer; font: inherit; }
        button:disabled { opacity: .6; cursor: wait; }
        ul { display: grid; gap: .55rem; padding: 0; list-style: none; }
        li { display: flex; flex-wrap: wrap; justify-content: space-between; gap: .25rem 1rem; padding: .75rem; background: #1b2330; border-radius: .4rem; }
        .result { color: #aab6c7; }
        .pass { color: #72d6a0; }
        .warning { color: #ffd166; }
        .fail { color: #ff8585; }
        .note { margin-top: 1rem; font-size: .9rem; }
        a { color: #8dbbff; }
        @media (max-width: 40rem) { body { margin-top: 1.5rem; } li { display: grid; } }
    </style>
</head>
<body>
    <h1>Перевірка доступу до файлів</h1>
    <p>Перевіряються лише наперед визначені URL методом HEAD. Для storage/ береться по одному наявному JSON і NDJSON-файлу. Вміст файлів не запитується та не відображається.</p>
    <?php if ($storageIsSymlink): ?>
        <p class="warning">Увага: storage/ є символічним посиланням. Перевірте його ціль і налаштування вебсервера вручну.</p>
    <?php endif; ?>
    <button id="run-check" type="button">Запустити перевірку</button>
    <ul id="checks" aria-live="polite">
        <?php foreach ($targets as $target): ?>
            <?php $hasPath = is_string($target['path']) && $target['path'] !== ''; ?>
            <?php $targetUrl = $hasPath
                ? checkSecurityAppUrl($target['path'], !empty($target['documentRootRelative']))
                : ''; ?>
            <li
                data-url="<?= htmlspecialchars($targetUrl, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?>"
                data-type="<?= htmlspecialchars($target['type'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?>"
                data-missing-label="<?= htmlspecialchars($target['missingLabel'] ?? 'Файл такого типу не знайдено; перевірку не виконано', ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?>"
            >
                <span><?= htmlspecialchars($target['label'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?></span>
                <strong class="result"><?= $hasPath ? 'Очікує перевірки' : htmlspecialchars($target['missingLabel'] ?? 'Файл такого типу не знайдено; перевірку не виконано', ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?></strong>
            </li>
        <?php endforeach; ?>
    </ul>
    <p class="note">403/401 означає, що сервер відмовив у доступі. 404 означає, що шлях не знайдено, але саме по собі не підтверджує правило блокування. Відповідь 2xx для статичного файла потребує негайної перевірки; для PHP-файла вона не доводить, що вихідний код було віддано.</p>
    <p><a href="adminpanel/admin.php">Повернутися до адмінпанелі</a></p>
    <script>
        const runButton = document.getElementById('run-check');
        const results = document.querySelectorAll('#checks li');

        runButton.addEventListener('click', async () => {
            runButton.disabled = true;
            runButton.textContent = 'Перевірка...';

            for (const row of results) {
                const result = row.querySelector('.result');
                const url = row.dataset.url;
                result.className = 'result';

                if (!url) {
                    result.textContent = row.dataset.missingLabel;
                    result.classList.add('warning');
                    continue;
                }

                const controller = new AbortController();
                const timeoutId = setTimeout(() => controller.abort(), 8000);
                try {
                    const response = await fetch(url, {
                        method: 'HEAD',
                        credentials: 'same-origin',
                        cache: 'no-store',
                        redirect: 'manual',
                        signal: controller.signal
                    });

                    if (response.status === 401 || response.status === 403) {
                        result.textContent = `Заблоковано (${response.status})`;
                        result.classList.add('pass');
                    } else if (response.status === 404) {
                        result.textContent = 'Не знайдено (захист не підтверджено)';
                        result.classList.add('warning');
                    } else if (response.status >= 200 && response.status < 300) {
                        result.textContent = row.dataset.type === 'php'
                            ? `URL відповів (${response.status}); перевірте обробку PHP`
                            : `URL доступний (${response.status})`;
                        result.classList.add('fail');
                    } else {
                        result.textContent = `Неоднозначна відповідь (${response.status || 'невідомо'})`;
                        result.classList.add('warning');
                    }
                } catch (error) {
                    result.textContent = 'Не вдалося перевірити з цього браузера';
                    result.classList.add('warning');
                } finally {
                    clearTimeout(timeoutId);
                }
            }

            runButton.disabled = false;
            runButton.textContent = 'Запустити перевірку';
        });
    </script>
</body>
</html>
