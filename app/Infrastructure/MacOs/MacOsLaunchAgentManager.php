<?php

declare(strict_types=1);

namespace App\Infrastructure\MacOs;

use App\Domain\AppDev\AppDevHostPaths;
use App\Domain\AppDev\RuntimeConvergenceException;
use App\Domain\Nodes\RoleName;
use App\Infrastructure\Processes\CommandResult;
use App\Infrastructure\Ssh\RemoteCommand;
use App\Infrastructure\Ssh\SshExecutor;
use App\Models\Node;
use InvalidArgumentException;

/**
 * @mago-expect lint:cyclomatic-complexity Launchd restoration preserves loaded and running state independently.
 * @mago-expect lint:kan-defect Exact snapshot and restoration branches fail closed on ambiguous native state.
 * @mago-expect lint:too-many-methods Narrow helpers keep each fixed launchd transition explicit.
 */
final readonly class MacOsLaunchAgentManager
{
    public function __construct(
        private MacOsSshConnectionFactory $connections,
        private SshExecutor $ssh,
        private MacOsSteadyStateCommandGuard $guard,
        private AppDevHostPaths $paths = new AppDevHostPaths,
        private MacOsFilesystemLayout $layout = new MacOsFilesystemLayout,
    ) {}

    /**
     * @param null|array{lock_path: string, token: string} $lease
     * @return array{user_id: string, loaded: bool, running: bool}
     */
    public function snapshot(Node $node, string $label, ?array $lease = null): array
    {
        $this->assertLabel($label);
        $this->assertLease($node, $label, $lease);
        $identity = $this->execute($node, new RemoteCommand(['/usr/bin/id', '-u']), $lease);
        $userId = trim($identity->stdout);

        if (! $identity->succeeded() || preg_match('/\A[1-9][0-9]*\z/D', $userId) !== 1) {
            throw $this->failure('launchd-snapshot', 'app-dev.launchd_snapshot_failed', $identity);
        }

        $state = $this->execute(
            $node,
            new RemoteCommand(['/bin/launchctl', 'print', "gui/{$userId}/{$label}"]),
            $lease,
        );
        $service = "gui/{$userId}/{$label}";

        if (! $state->succeeded()) {
            if (! $this->isLaunchdNotFound($state, $service)) {
                throw $this->failure('launchd-snapshot', 'app-dev.launchd_snapshot_failed', $state);
            }

            return [
                'user_id' => $userId,
                'loaded' => false,
                'running' => false,
            ];
        }

        $running = $this->runningState($state);

        if ($running === null) {
            throw $this->failure('launchd-snapshot', 'app-dev.launchd_snapshot_failed', $state);
        }

        return [
            'user_id' => $userId,
            'loaded' => true,
            'running' => $running,
        ];
    }

    /**
     * @param array{user_id: string, loaded: bool, running: bool} $previous
     * @param null|array{lock_path: string, token: string} $lease
     */
    public function activate(Node $node, string $label, string $plistPath, array $previous, ?array $lease = null): void
    {
        $this->assertTarget($node, $label, $plistPath, $previous);
        $this->assertLease($node, $label, $lease);
        $service = "gui/{$previous['user_id']}/{$label}";

        if ($previous['loaded']) {
            $bootout = $this->execute($node, new RemoteCommand(['/bin/launchctl', 'bootout', $service]), $lease);

            if (! $bootout->succeeded()) {
                throw $this->failure('launchd-activate', 'app-dev.launchd_activation_failed', $bootout);
            }
        }

        $bootstrap = $this->execute(
            $node,
            new RemoteCommand([
                '/bin/launchctl',
                'bootstrap',
                "gui/{$previous['user_id']}",
                $plistPath,
            ]),
            $lease,
        );

        if (! $bootstrap->succeeded()) {
            throw $this->failure('launchd-activate', 'app-dev.launchd_activation_failed', $bootstrap);
        }
    }

    /**
     * @param array{user_id: string, loaded: bool, running: bool} $previous
     * @param null|array{lock_path: string, token: string} $lease
     * @mago-expect lint:halstead Exact rollback restores loaded and running state independently.
     */
    public function restore(Node $node, string $label, string $plistPath, array $previous, ?array $lease = null): void
    {
        $this->assertTarget($node, $label, $plistPath, $previous);
        $this->assertLease($node, $label, $lease);
        $service = "gui/{$previous['user_id']}/{$label}";
        $current = $this->execute($node, new RemoteCommand(['/bin/launchctl', 'print', $service]), $lease);

        if (! $current->succeeded() && ! $this->isLaunchdNotFound($current, $service)) {
            throw $this->failure('launchd-rollback', 'app-dev.launchd_rollback_failed', $current);
        }

        if ($current->succeeded()) {
            if ($this->runningState($current) === null) {
                throw $this->failure('launchd-rollback', 'app-dev.launchd_rollback_failed', $current);
            }

            $bootout = $this->execute($node, new RemoteCommand(['/bin/launchctl', 'bootout', $service]), $lease);

            if (! $bootout->succeeded()) {
                throw $this->failure('launchd-rollback', 'app-dev.launchd_rollback_failed', $bootout);
            }
        }

        if (! $previous['loaded']) {
            return;
        }

        $bootstrap = $this->execute(
            $node,
            new RemoteCommand([
                '/bin/launchctl',
                'bootstrap',
                "gui/{$previous['user_id']}",
                $plistPath,
            ]),
            $lease,
        );

        if (! $bootstrap->succeeded()) {
            throw $this->failure('launchd-rollback', 'app-dev.launchd_rollback_failed', $bootstrap);
        }

        if (! $previous['running']) {
            $stop = $this->execute($node, new RemoteCommand(['/bin/launchctl', 'stop', $service]), $lease);

            if (! $stop->succeeded()) {
                throw $this->failure('launchd-rollback', 'app-dev.launchd_rollback_failed', $stop);
            }

            $restored = $this->execute($node, new RemoteCommand(['/bin/launchctl', 'print', $service]), $lease);

            if (! $restored->succeeded() || $this->runningState($restored) !== false) {
                throw $this->failure('launchd-rollback', 'app-dev.launchd_rollback_failed', $restored);
            }

            return;
        }

        $kickstart = $this->execute(
            $node,
            new RemoteCommand(['/bin/launchctl', 'kickstart', '-k', $service]),
            $lease,
        );

        if (! $kickstart->succeeded()) {
            throw $this->failure('launchd-rollback', 'app-dev.launchd_rollback_failed', $kickstart);
        }
    }

    /** @param null|array{lock_path: string, token: string} $lease */
    private function execute(Node $node, RemoteCommand $command, ?array $lease = null): CommandResult
    {
        if ($lease !== null) {
            $command = new RemoteCommand(
                arguments: ['/bin/bash', '-seu', '--', $lease['lock_path'], $lease['token'], ...$command->arguments],
                input: <<<'BASH'
                    lock_path=$1; token=$2; shift 2
                    test -d "$lock_path"; test ! -L "$lock_path"
                    test "$(cd "$lock_path" && pwd -P)" = "$lock_path"
                    test -f "$lock_path/owner"; test ! -L "$lock_path/owner"
                    test "$(/usr/bin/wc -l < "$lock_path/owner" | tr -d ' ')" = 1
                    read -r current_token keeper_pid extra < "$lock_path/owner"
                    test -z "${extra:-}"
                    test "$current_token" = "$token"
                    case "$keeper_pid" in ''|*[!0-9]*) exit 76 ;; esac
                    kill -0 "$keeper_pid" 2>/dev/null
                    keeper_command=$(/bin/ps -ww -p "$keeper_pid" -o command=)
                    case "$keeper_command" in
                        *"orbit-lease-keeper $token $lock_path") ;;
                        *) exit 76 ;;
                    esac
                    exec "$@"
                    BASH,
            );
        }

        return $this->ssh->execute(
            $this->connections->make($node),
            $this->guard->guard($command),
        );
    }

    /** @param null|array{lock_path: string, token: string} $lease */
    private function assertLease(Node $node, string $label, ?array $lease): void
    {
        if ($lease === null) {
            return;
        }

        $home = $this->paths->home($node, RoleName::AppDev);
        $expected = $label === 'com.orbit.caddy'
            ? $this->layout->caddyLock($home)
            : $this->layout->phpLock($home, substr($label, strlen('com.orbit.php-fpm.')));

        if (
            $lease['lock_path'] !== $expected
            || preg_match('/\A[a-f0-9]{24}\z/D', $lease['token']) !== 1
        ) {
            throw new InvalidArgumentException('The macOS launch agent lease is invalid.');
        }
    }

    /** @param array{user_id: string, loaded: bool, running: bool} $previous */
    private function assertTarget(Node $node, string $label, string $plistPath, array $previous): void
    {
        $this->assertLabel($label);
        $home = $this->paths->home($node, RoleName::AppDev);

        if (
            $plistPath !== $this->layout->launchAgent($home, $label)
            || preg_match('/\A[1-9][0-9]*\z/D', $previous['user_id']) !== 1
        ) {
            throw new InvalidArgumentException('The macOS launch agent target is invalid.');
        }
    }

    private function assertLabel(string $label): void
    {
        if (
            $label === 'com.orbit.caddy'
            || preg_match('/\Acom[.]orbit[.]php-fpm[.][0-9]+[.][0-9]+\z/D', $label) === 1
        ) {
            return;
        }

        throw new InvalidArgumentException('The macOS launch agent label is invalid.');
    }

    private function runningState(CommandResult $result): ?bool
    {
        $output = trim($result->stdout."\n".$result->stderr);
        $matches = [];
        $stateCount = preg_match_all(
            '/(?:\A|\R)state = ([^\r\n]*)(?=\R|\z)/D',
            $output,
            $matches,
        );

        if ($stateCount !== 1) {
            return null;
        }

        return match ($matches[1][0]) {
            'running' => true,
            'not running', 'stopped', 'waiting' => false,
            default => null,
        };
    }

    private function isLaunchdNotFound(CommandResult $result, string $service): bool
    {
        if ($result->succeeded()) {
            return false;
        }

        $output = trim($result->stdout."\n".$result->stderr);
        $segments = explode(separator: '/', string: $service, limit: 3);
        $canonical = count($segments) === 3
            ? sprintf(
                'Could not find service "%s" in domain for user gui: %s',
                $segments[2],
                $segments[1],
            )
            : null;

        return (
            in_array(
                $output,
                [
                    'Could not find service',
                    'service could not be found',
                    'No such process',
                    'Boot-out failed: 3: No such process',
                ],
                strict: true,
            )
            || $canonical !== null
            && $output === $canonical
            || $canonical !== null
            && $output === "Bad request.\n{$canonical}"
        );
    }

    private function failure(string $step, string $errorCode, CommandResult $result): RuntimeConvergenceException
    {
        return new RuntimeConvergenceException(
            step: $step,
            errorCode: $errorCode,
            message: 'The macOS launch agent operation failed.',
            result: $result,
        );
    }
}
