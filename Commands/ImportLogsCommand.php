<?php

namespace Piwik\Plugins\CustomImporter\Commands;

use Piwik\Plugin\ConsoleCommand;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

class ImportLogsCommand extends ConsoleCommand
{
    protected function configure()
    {
        parent::configure();
        $this->setName('customimporter:import')
            ->setDescription('Import Apache access logs containing Matomo tracking requests and replay them to the Tracking API');
        $this->addRequiredArgument('logfile', 'Path to Apache access log file');
        $this->addRequiredValueOption('matomo-url', null, 'Matomo base URL inc. scheme (e.g. https://matomo.loc)');
        $this->addOptionalValueOption('idsite', null, 'Matomo site id to attribute hits to (fallback if not in query)');
        $this->addOptionalValueOption('only-idsite', null, 'Process only log entries where original idsite equals this value');
        $this->addOptionalValueOption('token-auth', null, 'Matomo token_auth used when sending cip/cdt');
        $this->addOptionalValueOption('token-auth-env', null, 'Env var name to read token_auth from');
        $this->addOptionalValueOption('override-idsite', null, 'Force all hits to use this idsite (overrides any original)');
        $this->addNoValueOption('strip-auth-fields', null, 'Remove cip/cdt if no token_auth is provided');
        $this->addNoValueOption('dry-run', null, 'Parse and print but do not send to tracking API');
        $this->addNoValueOption('prefer-post', null, 'Send tracking request using HTTP POST instead of GET');
        $this->addNoValueOption('no-xff', null, 'Do not send X-Forwarded-For header even if token_auth is present');
        $this->addNoValueOption('no-fallback', null, 'Do not retry without auth fields; keep original cdt even on errors');
        $this->addOptionalValueOption('limit', null, 'Max number of lines to process', null);
        $this->addOptionalValueOption('sleep-us', null, 'Microseconds to sleep between requests', 0);
        $this->addNoValueOption('debug', null, 'Verbose debug output');
    }

    protected function doExecute(): int
    {
        $input = $this->getInput();
        $output = $this->getOutput();
        $logFile = $input->getArgument('logfile');
        $matomoUrl = rtrim((string) $input->getOption('matomo-url'), '/');
        $defaultIdSite = $input->getOption('idsite');
        $onlyIdSite = $input->getOption('only-idsite');
        $dryRun = (bool) $input->getOption('dry-run');
        $limit = $input->getOption('limit') !== null ? (int) $input->getOption('limit') : null;
        $sleepUs = (int) $input->getOption('sleep-us');
        $debug = (bool) $input->getOption('debug');
        $tokenAuth = $input->getOption('token-auth');
        $tokenAuthEnv = $input->getOption('token-auth-env');
        if (empty($tokenAuth) && !empty($tokenAuthEnv)) {
            $envVal = getenv($tokenAuthEnv);
            if (!empty($envVal)) {
                $tokenAuth = $envVal;
            }
        }
        $overrideIdSite = $input->getOption('override-idsite');
        $stripAuthFields = (bool) $input->getOption('strip-auth-fields');
        $preferPost = (bool) $input->getOption('prefer-post');
        $noXff = (bool) $input->getOption('no-xff');
        $noFallback = (bool) $input->getOption('no-fallback');

        if (!is_readable($logFile)) {
            throw new \InvalidArgumentException('Log file not readable: ' . $logFile);
        }
        if (!$dryRun && empty($matomoUrl)) {
            throw new \InvalidArgumentException('--matomo-url is required when not using --dry-run');
        }
        if (!$dryRun && empty($tokenAuth)) {
            throw new \InvalidArgumentException('--token-auth (or --token-auth-env) is required');
        }

        // Pre-scan to count how many lines we will actually process, for progress reporting
        $totalToProcess = 0;
        $scan = fopen($logFile, 'r');
        if ($scan === false) {
            throw new \RuntimeException('Failed to open log file: ' . $logFile);
        }
        while (!feof($scan)) {
            $line = fgets($scan);
            if ($line === false) { break; }
            $line = trim($line);
            if ($line === '') { continue; }
            $entry = $this->parseApacheCombinedLine($line);
            if (!$entry || !isset($entry['request_uri'])) { continue; }
            $path = parse_url($entry['request_uri'], PHP_URL_PATH) ?: '';
            if ($path !== '/matomo.php' && $path !== '/piwik.php') { continue; }
            $queryStringScan = parse_url($entry['request_uri'], PHP_URL_QUERY) ?: '';
            parse_str($queryStringScan, $paramsScan);
            $originalIdSite = isset($paramsScan['idsite']) ? (string) $paramsScan['idsite'] : null;
            if ($onlyIdSite !== null) {
                if ($originalIdSite === null || (string) $onlyIdSite !== $originalIdSite) {
                    continue;
                }
            }
            $totalToProcess++;
            if ($limit !== null && $totalToProcess >= $limit) { break; }
        }
        fclose($scan);

		$this->getOutput()->writeln('Total lines to process: ' . $totalToProcess);
		$startTime = microtime(true);

        $handle = fopen($logFile, 'r');
        if ($handle === false) {
            throw new \RuntimeException('Failed to open log file: ' . $logFile);
        }

		$processed = 0;
		$nextReportPct = ($totalToProcess > 0) ? 1 : 0;
        while (!feof($handle)) {
            $line = fgets($handle);
            if ($line === false) {
                break;
            }
            $line = trim($line);
            if ($line === '') {
                continue;
            }
            $entry = $this->parseApacheCombinedLine($line);
            if (!$entry) {
                if ($debug) {
                    $output->writeln('Skip unparsable line: ' . $line);
                }
                continue;
            }

            if (!isset($entry['timestamp']) || $entry['timestamp'] === null) {
                if ($debug) {
                    $rawDt = isset($entry['raw_datetime']) ? $entry['raw_datetime'] : '';
                    $output->writeln('[debug] Skip: failed to parse datetime: ' . $rawDt);
                }
                continue;
            }

            // Only handle requests to /matomo.php or /piwik.php (tracking endpoint)
            $path = parse_url($entry['request_uri'], PHP_URL_PATH) ?: '';
            if ($path !== '/matomo.php' && $path !== '/piwik.php') {
                continue;
            }

            $queryString = parse_url($entry['request_uri'], PHP_URL_QUERY) ?: '';
            parse_str($queryString, $params);

            // Filter by original idsite if requested
            $originalIdSite = isset($params['idsite']) ? (string) $params['idsite'] : null;
            if ($onlyIdSite !== null) {
                if ($originalIdSite === null || (string) $onlyIdSite !== $originalIdSite) {
                    continue;
                }
            }

            if (!empty($overrideIdSite)) {
                $params['idsite'] = $overrideIdSite;
            } elseif (!isset($params['idsite']) && $defaultIdSite) {
                $params['idsite'] = $defaultIdSite;
            }
            // Preserve timestamp and client info
            // Matomo Tracking API: cdt for datetime, cip for IP, ua via header
            if (!isset($params['cdt']) && isset($entry['timestamp'])) {
                // cdt must be UTC per Matomo doc
                $params['cdt'] = gmdate('Y-m-d H:i:s', (int) $entry['timestamp']);
            }
            if (!isset($params['cip']) && isset($entry['ip'])) {
                $params['cip'] = $entry['ip'];
            }
            // if cdt is present, remove h/m/s to avoid conflicts
            if (isset($params['cdt'])) {
                unset($params['h'], $params['m'], $params['s']);
            }
            if (($params['cip'] ?? null) || ($params['cdt'] ?? null)) {
                if (!isset($params['token_auth'])) {
                    if (!empty($tokenAuth)) {
                        $params['token_auth'] = $tokenAuth;
                    } elseif ($stripAuthFields) {
                        unset($params['cip'], $params['cdt']);
                    }
                }
            }

            // Always include API version marker
            $params['apiv'] = 1;

            $trackingUrl = $matomoUrl . '/matomo.php';
            $queryString = http_build_query($params);
            $finalUrl = $trackingUrl . '?' . $queryString;

            if ($dryRun) {
                $printUrl = $finalUrl;
                if (isset($params['token_auth'])) {
                    $printUrl = preg_replace('/(token_auth=)[^&]+/','${1}***', $printUrl);
                }
                $output->writeln(($dryRun ? '[DRY] ' : '') . $printUrl);
            }

            if (!$dryRun) {
                $headers = [
                    'User-Agent: ' . ($entry['user_agent'] ?? 'CustomImporter/1.0'),
                    'Referer: ' . ($entry['referer'] ?? ''),
                ];
                $hasToken = isset($params['token_auth']) && !empty($params['token_auth']);
                if ($hasToken && !$stripAuthFields && !$noXff && !empty($entry['ip'])) {
                    $headers[] = 'X-Forwarded-For: ' . $entry['ip'];
                }
                $status = $preferPost
                    ? $this->sendPost($trackingUrl, $queryString, $headers)
                    : $this->sendGet($finalUrl, $headers);

                // Fallback: if request failed and we used cip/cdt/token, retry once with safer params
                if ((int)$status >= 400 && !$noFallback) {
                    $usedAuthFields = isset($params['token_auth']) || isset($params['cip']) || isset($params['cdt']);
                    if ($usedAuthFields) {
                        $retryParams = $params;
                        if (isset($retryParams['token_auth']) && !empty($retryParams['token_auth'])) {
                            // keep token & cdt; only drop cip
                            unset($retryParams['cip']);
                        } else {
                            // no token available → drop cip & cdt to avoid tracker errors
                            unset($retryParams['cip'], $retryParams['cdt']);
                        }
                        $retryQuery = http_build_query($retryParams);
                        $retryUrl = $trackingUrl . '?' . $retryQuery;
                        $retryHeaders = [
                            'User-Agent: ' . ($entry['user_agent'] ?? 'CustomImporter/1.0'),
                            'Referer: ' . ($entry['referer'] ?? ''),
                        ];
                        $preferPost
                            ? $this->sendPost($trackingUrl, $retryQuery, $retryHeaders)
                            : $this->sendGet($retryUrl, $retryHeaders);
                    }
                }
                if ($sleepUs > 0) {
                    usleep($sleepUs);
                }
            }

			$processed++;
			if ($totalToProcess > 0) {
				$pct = (int) floor(($processed * 100) / $totalToProcess);
				while ($nextReportPct > 0 && $pct >= $nextReportPct && $nextReportPct <= 100) {
					$elapsed = microtime(true) - $startTime;
					$this->getOutput()->writeln('Progress: ' . $nextReportPct . '% (' . $processed . '/' . $totalToProcess . ') - elapsed: ' . number_format($elapsed, 2) . 's');
					$nextReportPct += 1;
				}
			}
            if ($limit !== null && $processed >= $limit) {
                break;
            }
        }

        fclose($handle);
        $output->writeln('Processed: ' . $processed . ' lines');
        return self::SUCCESS;
    }

    private function parseApacheCombinedLine($line)
    {
        // Combined Log Format: %h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-agent}i"
        $regex = '/^(\S+)\s+(\S+)\s+(\S+)\s+\[([^\]]+)\]\s+"([^"]*)"\s+(\d{3})\s+(\S+)\s+"([^"]*)"\s+"([^"]*)"/';
        if (!preg_match($regex, $line, $matches)) {
            return null;
        }

        $ip = $matches[1];
        $datetimeStr = $matches[4]; // e.g., 10/Oct/2000:13:55:36 -0700
        $request = $matches[5];
        $status = (int) $matches[6];
        $bytes = $matches[7] !== '-' ? (int) $matches[7] : 0;
        $referer = $matches[8] !== '-' ? $matches[8] : '';
        $userAgent = $matches[9] !== '-' ? $matches[9] : '';

        $timestamp = $this->parseApacheDateTimeToTimestamp($datetimeStr);
        $requestParts = explode(' ', $request, 3);
        $method = $requestParts[0] ?? '';
        $uri = $requestParts[1] ?? '';

        return [
            'ip' => $ip,
            'timestamp' => $timestamp,
            'raw_datetime' => $datetimeStr,
            'method' => $method,
            'request_uri' => $uri,
            'status' => $status,
            'bytes' => $bytes,
            'referer' => $referer,
            'user_agent' => $userAgent,
        ];
    }

    private function parseApacheDateTimeToTimestamp($dt)
    {
        // Expected Apache combined: d/M/Y:H:i:s O (e.g., 25/Sep/2025:11:24:17 +0000)
        $dt = trim($dt);
        $parsed = \DateTime::createFromFormat('d/M/Y:H:i:s O', $dt, new \DateTimeZone('UTC'));
        if ($parsed instanceof \DateTime) {
            return $parsed->getTimestamp();
        }
        // try without timezone (assume UTC)
        $parsed2 = \DateTime::createFromFormat('d/M/Y:H:i:s', $dt, new \DateTimeZone('UTC'));
        if ($parsed2 instanceof \DateTime) {
            return $parsed2->getTimestamp();
        }
        return null;
    }

    private function sendGet($url, array $headers)
    {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 30);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_HEADER, false);
        curl_exec($ch);
        $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        return $status;
    }

    private function sendPost($url, string $body, array $headers)
    {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
        $headers = array_merge(['Content-Type: application/x-www-form-urlencoded'], $headers);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 30);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_HEADER, false);
        curl_exec($ch);
        $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        return $status;
    }
}


