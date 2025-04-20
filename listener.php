<?php
// udp_listener.php - PHP 8.3+ with validation, metrics, log rotation, and socket_select()

pcntl_async_signals(true);

$options = getopt('', [
    'host::', 'iface::', 'port::', 'logfile::', 'ratelimit::', 'window::',
    'daemon', 'verbose', 'maxforks::', 'loglevel::', 'logrotate::', 'timeout::', 'help'
]);

if (isset($options['help'])) {
    echo <<<HELP
Usage: php udp_listener.php [options]

Options:
  --host=IP           Bind to specific IP address (optional if --iface is set)
  --iface=IFACE       Bind to all IPv4 addresses on the specified interface (e.g., eth0)
  --port=PORT         Port to listen on (default: 9999)
  --logfile=FILE      Path to log file (default: ./udp_log.txt)
  --logrotate=SIZE    Rotate log file if it exceeds SIZE in bytes (e.g. 1048576)
  --ratelimit=N       Max packets per IP per time window (default: 10)
  --window=SECONDS    Rate limit time window (default: 10)
  --maxforks=N        Max child processes allowed (default: 50)
  --timeout=MS        Socket select timeout in milliseconds (default: 200ms)
  --loglevel=LEVEL    Log level: debug, info, warn (default: info)
  --verbose           Enable verbose output (same as --loglevel=debug)
  --daemon            Run as background process (detach from terminal)
  --help              Show this help message
HELP;
    exit(0);
}

function validate_positive_int(mixed $val, int $default, string $name): int {
    if (!is_numeric($val) || (int)$val < 0) {
        log_message("Invalid --$name: must be a non-negative integer.", 'warn');
        return $default;
    }
    return (int)$val;
}

$host = $options['host'] ?? null;
$iface = $options['iface'] ?? null;
$listenPort = validate_positive_int($options['port'] ?? 9999, 9999, 'port');
$logFilePath = $options['logfile'] ?? __DIR__ . '/udp_log.txt';
$logRotateSize = validate_positive_int($options['logrotate'] ?? 0, 0, 'logrotate');
$rateLimit = validate_positive_int($options['ratelimit'] ?? 10, 10, 'ratelimit');
$rateWindow = validate_positive_int($options['window'] ?? 10, 10, 'window');
$maxForks = validate_positive_int($options['maxforks'] ?? 50, 50, 'maxforks');
$timeoutMs = validate_positive_int($options['timeout'] ?? 200, 200, 'timeout');
$logLevel = $options['loglevel'] ?? ($options['verbose'] ? 'debug' : 'info');

$running = true;
$logToFile = true;
$childPids = [];
$ipPacketCounts = [];
$ipTimestamps = [];
$droppedPackets = 0;
$skippedPackets = 0;
$lastStatsTime = time();
$statsInterval = 60;

function log_message(string $message, string $level = 'info'): void {
    global $logToFile, $logFilePath, $options, $logLevel, $logRotateSize;
    $levels = ['debug' => 0, 'info' => 1, 'warn' => 2];
    if ($levels[$level] < $levels[$logLevel]) return;

    $msg = "[$level] $message" . PHP_EOL;
    if (isset($options['daemon'])) {
        openlog("udp_listener", LOG_PID | LOG_PERROR, LOG_DAEMON);
        syslog(LOG_INFO, $message);
        closelog();
    } else {
        echo $msg;
        if ($logToFile) {
            if ($logRotateSize > 0 && file_exists($logFilePath) && filesize($logFilePath) >= $logRotateSize) {
                $backup = $logFilePath . '.' . date('Ymd_His');
                rename($logFilePath, $backup);
            }
            error_log($msg, 3, $logFilePath);
        }
    }
}

function debug_message(string $message): void {
    log_message($message, 'debug');
}

function get_interface_ips(string $iface): array {
    $ips = [];
    exec("ip -4 addr show dev " . escapeshellarg($iface), $output);
    foreach ($output as $line) {
        if (preg_match('/inet (\d+\.\d+\.\d+\.\d+)/', $line, $matches)) {
            $ips[] = $matches[1];
        }
    }
    return $ips;
}

if (isset($options['daemon'])) {
    $pid = pcntl_fork();
    if ($pid < 0) exit("Could not fork daemon\n");
    if ($pid > 0) exit(0);
    if (posix_setsid() < 0) exit("Could not setsid\n");
    fclose(STDIN);
    fclose(STDOUT);
    fclose(STDERR);
    fopen('/dev/null', 'r');
    fopen('/dev/null', 'w');
    fopen('/dev/null', 'w');
}

pcntl_signal(SIGINT, function () use (&$running, &$sockets, &$childPids, &$droppedPackets, &$skippedPackets) {
    log_message("Shutting down listener...", 'warn');
    log_message("Total dropped packets: $droppedPackets", 'info');
    log_message("Total skipped forks: $skippedPackets", 'info');
    foreach ($childPids as $pid) posix_kill($pid, SIGTERM);
    foreach ($sockets ?? [] as $sock) socket_close($sock);
    $running = false;
    exit(0);
});

pcntl_signal(SIGTERM, function () use (&$running, &$sockets, &$childPids, &$droppedPackets, &$skippedPackets) {
    log_message("SIGTERM received, shutting down.", 'warn');
    log_message("Total dropped packets: $droppedPackets", 'info');
    log_message("Total skipped forks: $skippedPackets", 'info');
    foreach ($childPids as $pid) posix_kill($pid, SIGTERM);
    foreach ($sockets ?? [] as $sock) socket_close($sock);
    $running = false;
    exit(0);
});

pcntl_signal(SIGCHLD, function () use (&$childPids) {
    while (($pid = pcntl_waitpid(-1, $status, WNOHANG)) > 0) unset($childPids[$pid]);
});

$sockets = [];
$bindIPs = $iface ? get_interface_ips($iface) : ($host ? [$host] : die("Specify --host or --iface\n"));

foreach ($bindIPs as $ip) {
    $sock = socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);
    socket_bind($sock, $ip, $listenPort) or die("Could not bind to $ip:$listenPort\n");
    socket_set_nonblock($sock);
    $sockets[] = $sock;
    log_message("Listening on UDP $ip:$listenPort", 'info');
}

while ($running) {
    $readSockets = $sockets;
    $write = $except = null;
    if (socket_select($readSockets, $write, $except, 0, $timeoutMs * 1000) > 0) {
        foreach ($readSockets as $sock) {
            $buf = '';
            $remoteHost = '';
            $remotePort = 0;
            socket_recvfrom($sock, $buf, 65535, 0, $remoteHost, $remotePort);
            if (!$buf) continue;

            debug_message("Packet from $remoteHost:$remotePort");
            $now = time();
            $ipPacketCounts[$remoteHost] = ($ipPacketCounts[$remoteHost] ?? 0) + 1;
            $ipTimestamps[$remoteHost] = $ipTimestamps[$remoteHost] ?? $now;

            if ($now - $ipTimestamps[$remoteHost] > $rateWindow) {
                $ipPacketCounts[$remoteHost] = 1;
                $ipTimestamps[$remoteHost] = $now;
            }

            if ($ipPacketCounts[$remoteHost] > $rateLimit) {
                log_message("[RATE-LIMIT] $remoteHost:$remotePort dropped", 'warn');
                $droppedPackets++;
                continue;
            }

            if (count($childPids) >= $maxForks) {
                log_message("[FORK-LIMIT] Skipped $remoteHost", 'warn');
                $skippedPackets++;
                continue;
            }
//          // By PHP documentation
//          $pid = pcntl_fork();
//          if ($pid == -1) {
//              die('could not fork');
//          } else if ($pid) {
//              // we are the parent
//              pcntl_wait($status); //Protect against Zombie children
//          } else {
//              // we are the child
//          }
//          //    Some hints:
//          //    - It is disabled by default. If you manage to enable it, then do it for CLI only.
//          //    - Never ever use it with web server! It will behave in non-deterministic way. It can also bring whole machine down. Please, leave it disabled and read on.
//          //    - Parent process have to wait for children to finish or it will leave zombie processes consuming system resources behind.
//          //      When the parent doesn’t acknowledge their completion, children remain in the zombie (Z, <defunct>) state.
//          //    - File descriptors (and database connections) are shared, this causes problems very often. You have to reconnect your DB after forking or you will get errors like MySQL server has gone away from all forked processes when first of them closes the connection.
//          //    - Communication between processes is possible but horrible (via serialized object in shared memory).

            $pid = pcntl_fork();
            if ($pid === -1) continue;
            if ($pid === 0) {
                $timestamp = date('Y-m-d H:i:s');
                $len = strlen($buf);
                log_message("[$timestamp] $remoteHost:$remotePort ($len bytes): " . trim($buf));
                exit(0);
            }
            $childPids[$pid] = $pid;
        }
    }
    if ((time() - $lastStatsTime) >= $statsInterval) {
        log_message("[STATS] Dropped packets: $droppedPackets, Skipped forks: $skippedPackets", 'info');
        $lastStatsTime = time();
    }
    while (($pid = pcntl_waitpid(-1, $status, WNOHANG)) > 0) unset($childPids[$pid]);
}
