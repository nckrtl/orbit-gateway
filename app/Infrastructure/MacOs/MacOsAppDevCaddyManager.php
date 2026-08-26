<?php

declare(strict_types=1);

namespace App\Infrastructure\MacOs;

use App\Domain\AppDev\AppDevCaddyManager;
use App\Domain\AppDev\AppDevHostPaths;
use App\Domain\AppDev\AppDevSourceOperationLock;
use App\Domain\AppDev\RuntimeConvergenceException;
use App\Domain\Nodes\RoleName;
use App\Infrastructure\AppDev\AppDevSiteRepository;
use App\Infrastructure\Processes\CommandResult;
use App\Infrastructure\Ssh\RemoteCommand;
use App\Infrastructure\Ssh\SshExecutor;
use App\Models\Node;
use Throwable;

/**
 * @mago-expect lint:cyclomatic-complexity Atomic publication and exact recovery use explicit failure gates.
 * @mago-expect lint:excessive-parameter-list Explicit transport, rendering, layout, launchd, and lock boundaries are required.
 * @mago-expect lint:kan-defect Atomic publication and exact recovery use explicit failure gates.
 * @mago-expect lint:too-many-methods Narrow methods keep adaptation, publication, launchd, and recovery steps distinct.
 */
final readonly class MacOsAppDevCaddyManager implements AppDevCaddyManager
{
    public function __construct(
        private AppDevSiteRepository $sites,
        private MacOsAppDevCaddyConfigRenderer $renderer,
        private AppDevHostPaths $paths,
        private MacOsFilesystemLayout $layout,
        private MacOsSshConnectionFactory $connections,
        private SshExecutor $ssh,
        private MacOsSteadyStateCommandGuard $guard,
        private MacOsLaunchAgentManager $launchAgents,
        private AppDevSourceOperationLock $lock,
    ) {}

    /** @mago-expect lint:halstead The method preserves publication and launchd recovery order. */
    public function converge(Node $node): void
    {
        $this->lock->synchronized($node->id, function () use ($node): void {
            $home = $this->paths->home($node, RoleName::AppDev);
            $caddy = $this->caddyBinary($node);
            $address = $node->wireguard_address;

            if (! is_string($address)) {
                throw new RuntimeConvergenceException(
                    step: 'caddy-config',
                    errorCode: 'app-dev.caddy_address_invalid',
                    message: 'The macOS Caddy listener address is missing.',
                );
            }

            $configuration = $this->renderer->render($this->sites->forNode($node), $address);
            $adapted = $this->execute($node, new RemoteCommand(
                arguments: [$caddy, 'adapt', '--config', '-', '--adapter', 'caddyfile', '--validate'],
                input: $configuration,
            ));

            if (! $adapted->succeeded()) {
                throw $this->failure('caddy-adapt', 'app-dev.caddy_adaptation_failed', $adapted);
            }

            $this->assertAdaptedConfiguration($adapted->stdout, $address);

            $label = 'com.orbit.caddy';
            $plist = $this->layout->launchAgent($home, $label);
            $token = bin2hex(random_bytes(12));
            $lockPath = $this->layout->caddyLock($home);
            $this->acquireTargetLock($node, $home, $lockPath, $token);
            $lease = ['lock_path' => $lockPath, 'token' => $token];
            $primaryFailure = null;

            try {
                $state = $this->launchAgents->snapshot($node, $label, $lease);
                try {
                    $publication = $this->publish(
                        node: $node,
                        configuration: $configuration,
                        plistContents: $this->plist($node, $caddy, $home),
                        caddy: $caddy,
                        liveConfiguration: $this->layout->caddyCurrent($home),
                        plist: $plist,
                        lockPath: $lockPath,
                        token: $token,
                        expectedAdaptedHash: hash('sha256', rtrim($adapted->stdout, characters: "\n")),
                    );
                } catch (Throwable) {
                    $this->restorePublishedState($node, $home, $label, $plist, $token, $state, $lease);

                    throw new RuntimeConvergenceException(
                        step: 'caddy-config',
                        errorCode: 'app-dev.caddy_config_failed',
                        message: 'The macOS Caddy operation failed.',
                    );
                }

                if ($publication->exitCode === 76) {
                    throw $this->failure('caddy-rollback', 'app-dev.caddy_rollback_failed', $publication);
                }

                if (! $publication->succeeded()) {
                    $publicationFailure = $this->failure(
                        'caddy-config',
                        'app-dev.caddy_config_failed',
                        $publication,
                    );

                    if ($publication->exitCode === 255) {
                        $this->restorePublishedState($node, $home, $label, $plist, $token, $state, $lease);
                    }

                    throw $publicationFailure;
                }

                if (trim($publication->stdout) === 'UNCHANGED') {
                    return;
                }

                try {
                    $this->launchAgents->activate($node, $label, $plist, $state, $lease);
                } catch (Throwable $activationFailure) {
                    $this->restorePublishedState($node, $home, $label, $plist, $token, $state, $lease);

                    throw $activationFailure;
                }

                $this->cleanup($node, $home, $token);
            } catch (Throwable $caught) {
                $primaryFailure = $caught;

                throw $caught;
            } finally {
                $this->releaseTargetLockPreservingPrimary($node, $lockPath, $token, $primaryFailure);
            }
        });
    }

    /** @mago-expect lint:sensitive-parameter The random lease token is an identifier, not a credential. */
    private function releaseTargetLockPreservingPrimary(
        Node $node,
        string $lockPath,
        string $token,
        ?Throwable $primaryFailure,
    ): void {
        try {
            $this->releaseTargetLock($node, $lockPath, $token);
        } catch (Throwable $releaseFailure) {
            if ($primaryFailure === null) {
                throw $releaseFailure;
            }

            report($releaseFailure);
        }
    }

    /** @mago-expect analysis:mixed-assignment Adapted Caddy JSON is validated before each value is used. */
    private function assertAdaptedConfiguration(string $json, string $address): void
    {
        try {
            $adapted = json_decode($json, associative: true, flags: JSON_THROW_ON_ERROR);
        } catch (\JsonException $exception) {
            throw new RuntimeConvergenceException(
                step: 'caddy-adapt',
                errorCode: 'app-dev.caddy_adaptation_invalid',
                message: 'Caddy returned invalid adapted configuration.',
                previous: $exception,
            );
        }

        $this->assertNoUnexpectedListeners($adapted);

        $apps = is_array($adapted) ? $adapted['apps'] ?? null : null;
        $http = is_array($apps) ? $apps['http'] ?? null : null;
        $servers = is_array($http) ? $http['servers'] ?? null : null;
        $listeners = [];
        $httpsProtocols = null;

        if (! is_array($servers) || ($adapted['admin'] ?? null) !== ['disabled' => true]) {
            $this->invalidAdaptation();
        }

        foreach ($servers as $server) {
            if (! is_array($server) || ! is_array($server['listen'] ?? null)) {
                $this->invalidAdaptation();
            }

            $protocols = null;

            if (array_key_exists('protocols', $server)) {
                if (! is_array($server['protocols'])) {
                    $this->invalidAdaptation();
                }

                $protocols = [];

                foreach ($server['protocols'] as $protocol) {
                    if (! is_string($protocol) || ! in_array(needle: $protocol, haystack: ['h1', 'h2'], strict: true)) {
                        $this->invalidAdaptation();
                    }

                    $protocols[] = $protocol;
                }
            }

            foreach ($server['listen'] as $listener) {
                if (! is_string($listener)) {
                    $this->invalidAdaptation();
                }

                $listeners[] = $listener;

                if ($listener === "{$address}:8443") {
                    $httpsProtocols = $protocols;
                }
            }
        }

        sort($listeners);
        $expected = ["{$address}:8080", "{$address}:8443"];
        sort($expected);

        if ($listeners !== $expected || implode(' ', $httpsProtocols ?? []) !== 'h1 h2') {
            $this->invalidAdaptation();
        }
    }

    private function invalidAdaptation(): never
    {
        throw new RuntimeConvergenceException(
            step: 'caddy-adapt',
            errorCode: 'app-dev.caddy_adaptation_invalid',
            message: 'The adapted Caddy listeners are not restricted to the WireGuard address.',
        );
    }

    /**
     * @param list<int|string> $path
     * @mago-expect analysis:mixed-assignment Adapted JSON remains mixed until each recursive value is checked.
     */
    private function assertNoUnexpectedListeners(mixed $value, array $path = []): void
    {
        if (! is_array($value)) {
            return;
        }

        foreach ($value as $key => $child) {
            if (
                $key === 'listen'
                && ! (count($path) === 4
                && $path[0] === 'apps'
                && $path[1] === 'http'
                && $path[2] === 'servers'
                && is_string($path[3]))
            ) {
                $this->invalidAdaptation();
            }

            $this->assertNoUnexpectedListeners($child, [...$path, $key]);
        }
    }

    /** @mago-expect lint:sensitive-parameter The random lease token is an identifier, not a credential. */
    private function acquireTargetLock(Node $node, string $home, string $lockPath, string $token): void
    {
        $result = $this->execute($node, new RemoteCommand(
            arguments: ['/bin/bash', '-seu', '--', $home, $lockPath, $token],
            input: <<<'BASH'
                home=$1; lock_path=$2; token=$3
                test -d "$home"; test ! -L "$home"
                test "$(cd "$home" && pwd -P)" = "$home"
                test "$lock_path" = "$home/.orbit/run/caddy.lock"
                for setup_directory in "$home/.orbit" "$home/.orbit/run"; do
                    test -d "$setup_directory"; test ! -L "$setup_directory"
                    test "$(cd "$setup_directory" && pwd -P)" = "$setup_directory"
                done
                if [ -L "$lock_path" ]; then exit 76; fi
                if [ -e "$lock_path" ]; then
                    test -d "$lock_path" || exit 76
                    test "$(cd "$lock_path" && pwd -P)" = "$lock_path" || exit 76
                    test -f "$lock_path/owner" || exit 76
                    test ! -L "$lock_path/owner" || exit 76
                    test "$(/usr/bin/wc -l < "$lock_path/owner" | tr -d ' ')" = 1 || exit 76
                    read -r previous_token previous_keeper_pid extra < "$lock_path/owner" || exit 76
                    if [ -n "${extra:-}" ] || [[ ! "$previous_token" =~ ^[a-f0-9]{24}$ ]]; then exit 76; fi
                    case "$previous_keeper_pid" in ''|*[!0-9]*) exit 76 ;; esac
                    if kill -0 "$previous_keeper_pid" 2>/dev/null; then
                        previous_keeper_command=$(/bin/ps -ww -p "$previous_keeper_pid" -o command=) || exit 76
                        case "$previous_keeper_command" in
                            *"orbit-lease-keeper $previous_token $lock_path") exit 75 ;;
                            *) exit 76 ;;
                        esac
                    elif /bin/ps -p "$previous_keeper_pid" -o pid= >/dev/null 2>&1; then
                        exit 76
                    fi
                    stale_lock="$lock_path.stale-$previous_token"
                    if [ -e "$stale_lock" ] || [ -L "$stale_lock" ]; then exit 76; fi
                    mv -h -- "$lock_path" "$stale_lock"
                fi
                if ! mkdir -- "$lock_path"; then exit 75; fi
                chmod 0700 "$lock_path"
                keeper_pid=
                release_failed_acquisition() {
                    status=$?
                    if [ "$status" -ne 0 ]; then
                        if [ ! -e "$lock_path/owner" ] && [ ! -L "$lock_path/owner" ]; then
                            rmdir -- "$lock_path" 2>/dev/null || true
                        elif [ -f "$lock_path/owner" ] && [ ! -L "$lock_path/owner" ] && read -r cleanup_token cleanup_keeper_pid cleanup_extra < "$lock_path/owner"; then
                            if [ "$cleanup_token" = "$token" ] && [ "$cleanup_keeper_pid" = "$keeper_pid" ] && [ -z "${cleanup_extra:-}" ]; then
                                rm -f -- "$lock_path/owner"
                                rmdir -- "$lock_path" 2>/dev/null || true
                            fi
                        fi
                        if [ -n "$keeper_pid" ]; then
                            kill "$keeper_pid" 2>/dev/null || true
                        fi
                    fi
                    exit "$status"
                }
                trap release_failed_acquisition EXIT
                /usr/bin/nohup /bin/sh -c '
                    token=$1; lock_path=$2; owner="$lock_path/owner"
                    umask 077
                    set -C
                    printf "%s %s\n" "$token" "$$" > "$owner"
                    set +C
                    while [ -d "$lock_path" ] && [ ! -L "$lock_path" ] && [ -f "$owner" ] && [ ! -L "$owner" ]; do
                        read -r current_token current_keeper_pid current_extra < "$owner" || exit 0
                        [ "$current_token" = "$token" ] && [ "$current_keeper_pid" = "$$" ] && [ -z "${current_extra:-}" ] || exit 0
                        /bin/sleep 5
                    done
                ' orbit-lease-keeper "$token" "$lock_path" </dev/null >/dev/null 2>&1 &
                keeper_pid=$!
                attempts=0
                while [ "$attempts" -lt 50 ] && [ ! -f "$lock_path/owner" ]; do
                    kill -0 "$keeper_pid" 2>/dev/null || exit 76
                    /bin/sleep 0.1
                    attempts=$((attempts + 1))
                done
                test -f "$lock_path/owner"; test ! -L "$lock_path/owner"
                test "$(/usr/bin/wc -l < "$lock_path/owner" | tr -d ' ')" = 1
                read -r current_token current_keeper_pid current_extra < "$lock_path/owner"
                test "$current_token" = "$token"; test "$current_keeper_pid" = "$keeper_pid"; test -z "${current_extra:-}"
                kill -0 "$keeper_pid" 2>/dev/null
                keeper_command=$(/bin/ps -ww -p "$keeper_pid" -o command=)
                case "$keeper_command" in *"orbit-lease-keeper $token $lock_path") ;; *) exit 76 ;; esac
                for managed_directory in "$home/.orbit/caddy" "$home/.orbit/caddy/versions" "$home/.orbit/logs" "$home/Library" "$home/Library/LaunchAgents"; do
                    if [ -L "$managed_directory" ]; then exit 1; fi
                    if [ -e "$managed_directory" ]; then test -d "$managed_directory"; else mkdir -- "$managed_directory"; chmod 0700 "$managed_directory"; fi
                    test ! -L "$managed_directory"
                    test "$(cd "$managed_directory" && pwd -P)" = "$managed_directory"
                done
                trap - EXIT
                printf 'ACQUIRED\n'
                BASH,
        ));

        if (! $result->succeeded() || trim($result->stdout) !== 'ACQUIRED') {
            throw $this->failure('caddy-lock', 'app-dev.caddy_lock_failed', $result);
        }
    }

    /** @mago-expect lint:sensitive-parameter The random lease token is an identifier, not a credential. */
    private function releaseTargetLock(Node $node, string $lockPath, string $token): void
    {
        $result = $this->execute($node, new RemoteCommand(
            arguments: ['/bin/bash', '-seu', '--', $lockPath, $token],
            input: <<<'BASH'
                lock_path=$1; token=$2
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
                case "$keeper_command" in *"orbit-lease-keeper $token $lock_path") ;; *) exit 76 ;; esac
                rm -f -- "$lock_path/owner"
                rmdir -- "$lock_path"
                kill "$keeper_pid" 2>/dev/null || true
                BASH,
        ));

        if (! $result->succeeded()) {
            throw $this->failure('caddy-lock-release', 'app-dev.caddy_lock_release_failed', $result);
        }
    }

    /**
     * @mago-expect lint:excessive-parameter-list Atomic publication needs each exact target and payload.
     * @mago-expect lint:sensitive-parameter The rendered Caddy configuration contains paths but no private key material.
     */
    private function publish(
        Node $node,
        string $configuration,
        string $plistContents,
        string $caddy,
        string $liveConfiguration,
        string $plist,
        string $lockPath,
        string $token,
        string $expectedAdaptedHash,
    ): CommandResult {
        $configurationEncoded = base64_encode($configuration);
        $plistEncoded = base64_encode($plistContents);
        $caddyRoot = dirname($liveConfiguration);
        $rollback = "{$this->paths->home($node, RoleName::AppDev)}/.orbit/run/.caddy-rollback-{$token}";
        $recoveryFunctions = $this->publicationRecoveryFunctions();
        $script = <<<BASH
            live_configuration=\$1
            plist=\$2
            caddy_root=\$3
            caddy=\$4
            lock_path=\$5
            rollback=\$6
            token=\$7
            expected_adapted_hash=\$8
            expected_user=\$(/usr/bin/id -un)
            expected_label='com.orbit.caddy'
            umask 077
            test -d "\$lock_path"
            test ! -L "\$lock_path"
            test "\$(cd "\$lock_path" && pwd -P)" = "\$lock_path"
            test -f "\$lock_path/owner"
            test ! -L "\$lock_path/owner"
            test "\$(/usr/bin/wc -l < "\$lock_path/owner" | tr -d ' ')" = 1
            read -r current_token keeper_pid extra < "\$lock_path/owner"
            test -z "\${extra:-}"
            test "\$current_token" = "\$token"
            case "\$keeper_pid" in ''|*[!0-9]*) exit 76 ;; esac
            kill -0 "\$keeper_pid" 2>/dev/null
            keeper_command=\$(/bin/ps -ww -p "\$keeper_pid" -o command=)
            case "\$keeper_command" in *"orbit-lease-keeper \$token \$lock_path") ;; *) exit 76 ;; esac
            rollback_parent=\$(dirname "\$rollback")
            plist_parent=\$(dirname "\$plist")
            live_parent="\$caddy_root"
            test "\$rollback_parent" = "\$(dirname "\$lock_path")"
            for managed_directory in "\$caddy_root" "\$caddy_root/versions" "\$rollback_parent" "\$plist_parent"; do
                test -d "\$managed_directory"
                test ! -L "\$managed_directory"
                test "\$(cd "\$managed_directory" && pwd -P)" = "\$managed_directory"
            done
            candidate_directory="\$caddy_root/versions/\$token.candidate"
            published_directory="\$caddy_root/versions/\$token"
            candidate_configuration="\$candidate_directory/Caddyfile"
            candidate_plist="\$candidate_directory/$(basename "{$plist}")"
            published_configuration="\$published_directory/Caddyfile"
            test ! -e "\$candidate_directory"; test ! -L "\$candidate_directory"
            test ! -e "\$rollback"; test ! -L "\$rollback"
            mkdir -m 0700 -- "\$candidate_directory" "\$rollback"
            printf '%s' '{$configurationEncoded}' | /usr/bin/base64 --decode > "\$candidate_configuration"
            printf '%s' '{$plistEncoded}' | /usr/bin/base64 --decode > "\$candidate_plist"
            chmod 0600 "\$candidate_configuration" "\$candidate_plist"
            adapted_json=\$("\$caddy" adapt --config "\$candidate_configuration" --adapter caddyfile --validate)
            actual_adapted_hash=\$(printf '%s' "\$adapted_json" | /usr/bin/shasum -a 256 | /usr/bin/awk '{print \$1}')
            test "\$actual_adapted_hash" = "\$expected_adapted_hash"
            /usr/bin/plutil -lint "\$candidate_plist"
            test "\$(/usr/bin/plutil -extract Label raw -o - "\$candidate_plist")" = "\$expected_label"
            {$recoveryFunctions}
            validate_managed_directory "\$live_parent"
            validate_managed_directory "\$plist_parent"
            validate_managed_directory "\$rollback_parent"
            validate_managed_directory "\$caddy_root/versions"
            validate_private_directory "\$candidate_directory"
            validate_private_directory "\$rollback"
            if [ -e "\$live_configuration" ] && cmp -s -- "\$candidate_configuration" "\$live_configuration" && [ -e "\$plist" ] && cmp -s -- "\$candidate_plist" "\$plist"; then
                validate_managed_directory "\$caddy_root"
                validate_managed_directory "\$rollback_parent"
                validate_private_directory "\$candidate_directory"
                validate_regular_file "\$candidate_configuration" '600'
                validate_regular_file "\$candidate_plist" '600'
                /bin/rm -- "\$candidate_configuration" "\$candidate_plist"
                /bin/rmdir -- "\$candidate_directory"
                validate_private_directory "\$rollback"
                /bin/rmdir -- "\$rollback"
                printf 'UNCHANGED\n'
                exit 0
            fi
            snapshot_path "\$live_configuration" configuration
            snapshot_path "\$plist" plist
            validate_rollback_artifacts
            switched=0
            rollback_on_error() {
                status=\$?
                recovery_failed=0
                if [ "\$status" -ne 0 ] && [ "\$switched" -eq 1 ]; then
                    restore_path "\$live_configuration" configuration || recovery_failed=1
                    restore_path "\$plist" plist || recovery_failed=1
                    if [ "\$recovery_failed" -eq 0 ]; then
                        path_matches_snapshot "\$live_configuration" configuration || recovery_failed=1
                        path_matches_snapshot "\$plist" plist || recovery_failed=1
                    fi
                    if [ "\$recovery_failed" -eq 0 ]; then
                        delete_rollback_artifacts || recovery_failed=1
                    fi
                fi
                if [ "\$recovery_failed" -eq 1 ]; then exit 76; fi
                exit "\$status"
            }
            trap rollback_on_error EXIT
            mv -- "\$candidate_directory" "\$published_directory"
            configuration_link="\$caddy_root/.Caddyfile.\$token.link"
            ln -s -- "\$published_directory/Caddyfile" "\$configuration_link"
            switched=1
            mv -h -f -- "\$configuration_link" "\$live_configuration"
            plist_candidate="\$(dirname "\$plist")/.\$(basename "\$plist").\$token.candidate"
            cp -p -- "\$published_directory/$(basename "{$plist}")" "\$plist_candidate"
            mv -h -f -- "\$plist_candidate" "\$plist"
            switched=0
            printf 'CHANGED\n'
            BASH;

        return $this->execute($node, new RemoteCommand(
            arguments: [
                '/bin/bash',
                '-seu',
                '--',
                $liveConfiguration,
                $plist,
                $caddyRoot,
                $caddy,
                $lockPath,
                $rollback,
                $token,
                $expectedAdaptedHash,
            ],
            input: $script,
        ));
    }

    private function publicationRecoveryFunctions(): string
    {
        return <<<'BASH'
            validate_managed_directory() {
                managed_directory=$1
                test -d "$managed_directory"; test ! -L "$managed_directory"
                test "$(cd "$managed_directory" && pwd -P)" = "$managed_directory"
                test "$(/usr/bin/stat -f '%Su' "$managed_directory")" = "$expected_user"
            }
            validate_private_directory() {
                private_directory=$1
                test -d "$private_directory"; test ! -L "$private_directory"
                test "$(cd "$private_directory" && pwd -P)" = "$private_directory"
                test "$(/usr/bin/stat -f '%Su' "$private_directory")" = "$expected_user"
                test "$(/usr/bin/stat -f '%Lp' "$private_directory")" = '700'
            }
            validate_regular_file() {
                regular_file=$1; expected_mode=$2
                test -f "$regular_file"; test ! -L "$regular_file"
                test "$(/usr/bin/stat -f '%Su' "$regular_file")" = "$expected_user"
                test "$(/usr/bin/stat -f '%Lp' "$regular_file")" = "$expected_mode"
            }
            validate_plist_target() {
                plist_target=$1
                test -f "$plist_target"; test ! -L "$plist_target"
                test "$(/usr/bin/stat -f '%Su' "$plist_target")" = "$expected_user"
                case "$(/usr/bin/stat -f '%Lp' "$plist_target")" in 600|644) ;; *) return 1 ;; esac
                test "$(/usr/bin/plutil -extract Label raw -o - "$plist_target")" = "$expected_label"
            }
            resolve_plist_target() {
                linked_plist_target=$1
                case "$linked_plist_target" in
                    /*) linked_plist="$linked_plist_target" ;;
                    *) linked_plist="$plist_parent/$linked_plist_target" ;;
                esac
            }
            validate_artifact() {
                artifact=$1
                test -f "$artifact"; test ! -L "$artifact"
                test "$(/usr/bin/stat -f '%Su' "$artifact")" = "$expected_user"
                artifact_mode=$(/usr/bin/stat -f '%Lp' "$artifact")
                case "$artifact" in
                    *.file) case "$artifact_mode" in 600|644) ;; *) return 1 ;; esac ;;
                    *) test "$artifact_mode" = '600' ;;
                esac
            }
            snapshot_path() {
                path=$1; name=$2
                if [ -L "$path" ]; then
                    test "$(/usr/bin/stat -f '%Su' "$path")" = "$expected_user"
                    link_target=$(/usr/bin/readlink "$path")
                    if [ "$name" = 'plist' ]; then
                        resolve_plist_target "$link_target"
                        validate_plist_target "$linked_plist"
                    fi
                    /usr/bin/printf '%s\n' "$link_target" > "$rollback/$name.link"
                    /bin/chmod 0600 "$rollback/$name.link"
                elif [ -f "$path" ]; then
                    test "$(/usr/bin/stat -f '%Su' "$path")" = "$expected_user"
                    case "$(/usr/bin/stat -f '%Lp' "$path")" in 600|644) ;; *) return 1 ;; esac
                    if [ "$name" = 'plist' ]; then validate_plist_target "$path"; fi
                    /bin/cp -p -- "$path" "$rollback/$name.file"
                elif [ ! -e "$path" ]; then
                    : > "$rollback/$name.missing"
                    /bin/chmod 0600 "$rollback/$name.missing"
                else
                    return 1
                fi
            }
            validate_rollback_artifacts() {
                validate_managed_directory "$rollback_parent"
                validate_private_directory "$rollback"
                for snapshot_name in configuration plist; do
                    marker_count=0
                    for suffix in link file missing; do
                        artifact="$rollback/$snapshot_name.$suffix"
                        if [ -e "$artifact" ] || [ -L "$artifact" ]; then
                            marker_count=$((marker_count + 1))
                            validate_artifact "$artifact"
                            if [ "$suffix" = 'missing' ]; then test ! -s "$artifact"; fi
                            if [ "$suffix" = 'link' ]; then
                                test "$(/usr/bin/wc -l < "$artifact" | /usr/bin/tr -d ' ')" = 1
                                test -n "$(/bin/cat "$artifact")"
                            fi
                        fi
                    done
                    test "$marker_count" = 1
                done
                for artifact in "$rollback"/*; do
                    case "$(/usr/bin/basename "$artifact")" in
                        configuration.link|configuration.file|configuration.missing|plist.link|plist.file|plist.missing) ;;
                        *) return 1 ;;
                    esac
                done
                if [ -f "$rollback/plist.file" ]; then validate_plist_target "$rollback/plist.file"; fi
                if [ -f "$rollback/plist.link" ]; then
                    resolve_plist_target "$(/bin/cat "$rollback/plist.link")"
                    validate_plist_target "$linked_plist"
                fi
            }
            path_matches_snapshot() {
                path=$1; name=$2
                if [ -f "$rollback/$name.link" ]; then
                    [ -L "$path" ] \
                        && [ "$(/usr/bin/stat -f '%Su' "$path")" = "$expected_user" ] \
                        && [ "$(/usr/bin/readlink "$path")" = "$(/bin/cat "$rollback/$name.link")" ] \
                        || return 1
                    if [ "$name" = 'plist' ]; then
                        resolve_plist_target "$(/usr/bin/readlink "$path")"
                        validate_plist_target "$linked_plist"
                    fi
                elif [ -f "$rollback/$name.file" ]; then
                    [ -f "$path" ] && [ ! -L "$path" ] \
                        && [ "$(/usr/bin/stat -f '%Su' "$path")" = "$expected_user" ] \
                        && [ "$(/usr/bin/stat -f '%Lp' "$path")" = "$(/usr/bin/stat -f '%Lp' "$rollback/$name.file")" ] \
                        && /usr/bin/cmp -s -- "$path" "$rollback/$name.file"
                else
                    test -f "$rollback/$name.missing" && [ ! -e "$path" ] && [ ! -L "$path" ]
                fi
            }
            validate_current_publication() {
                path=$1; name=$2
                if [ "$name" = 'configuration' ]; then
                    test -L "$path"
                    test "$(/usr/bin/stat -f '%Su' "$path")" = "$expected_user"
                    test "$(/usr/bin/readlink "$path")" = "$published_configuration"
                else
                    published_plist="$published_directory/$(/usr/bin/basename "$plist")"
                    validate_regular_file "$path" '600'
                    validate_regular_file "$published_plist" '600'
                    validate_plist_target "$path"
                    /usr/bin/cmp -s -- "$path" "$published_plist"
                fi
            }
            validate_restore_directory() {
                validate_private_directory "$restore_directory"
            }
            validate_restore_candidate() {
                restore_candidate=$1; name=$2
                if [ -f "$rollback/$name.link" ]; then
                    test -L "$restore_candidate"
                    test "$(/usr/bin/stat -f '%Su' "$restore_candidate")" = "$expected_user"
                    test "$(/usr/bin/readlink "$restore_candidate")" = "$(/bin/cat "$rollback/$name.link")"
                    if [ "$name" = 'plist' ]; then
                        resolve_plist_target "$(/usr/bin/readlink "$restore_candidate")"
                        validate_plist_target "$linked_plist"
                    fi
                else
                    validate_regular_file "$restore_candidate" "$(/usr/bin/stat -f '%Lp' "$rollback/$name.file")"
                    /usr/bin/cmp -s -- "$restore_candidate" "$rollback/$name.file"
                    if [ "$name" = 'plist' ]; then validate_plist_target "$restore_candidate"; fi
                fi
            }
            stage_restore_candidate() {
                path=$1; name=$2
                if [ -f "$rollback/$name.missing" ]; then
                    restore_directory=''; restore_candidate=''; return
                fi
                restore_parent=$(/usr/bin/dirname "$path")
                validate_managed_directory "$restore_parent"
                restore_directory="$restore_parent/.orbit-restore-$token-$name"
                if ! /bin/mkdir -m 0700 -- "$restore_directory"; then return 1; fi
                validate_restore_directory
                restore_candidate="$restore_directory/restored"
                if [ -f "$rollback/$name.link" ]; then
                    /bin/ln -s -- "$(/bin/cat "$rollback/$name.link")" "$restore_candidate"
                else
                    /bin/cp -p -- "$rollback/$name.file" "$restore_candidate"
                fi
                validate_restore_directory
                validate_restore_candidate "$restore_candidate" "$name"
            }
            restore_path() {
                path=$1; name=$2
                if path_matches_snapshot "$path" "$name"; then return; fi
                stage_restore_candidate "$path" "$name"
                validate_rollback_artifacts
                if [ "$name" = 'configuration' ]; then
                    validate_managed_directory "$live_parent"
                else
                    validate_managed_directory "$plist_parent"
                fi
                validate_current_publication "$path" "$name"
                if [ -n "$restore_candidate" ]; then
                    validate_restore_directory
                    validate_restore_candidate "$restore_candidate" "$name"
                    /bin/mv -h -f -- "$restore_candidate" "$path"
                    validate_restore_directory
                    /bin/rmdir -- "$restore_directory"
                else
                    validate_artifact "$rollback/$name.missing"
                    /bin/rm -f -- "$path"
                fi
                path_matches_snapshot "$path" "$name"
            }
            validate_artifact_for_delete() {
                artifact=$1; snapshot_name=$2; suffix=$3
                validate_artifact "$artifact"
                case "$suffix" in
                    missing) test ! -s "$artifact" ;;
                    link)
                        test "$(/usr/bin/wc -l < "$artifact" | /usr/bin/tr -d ' ')" = 1
                        link_target=$(/bin/cat "$artifact")
                        test -n "$link_target"
                        if [ "$snapshot_name" = 'plist' ]; then
                            resolve_plist_target "$link_target"
                            validate_plist_target "$linked_plist"
                        fi
                        ;;
                    file)
                        if [ "$snapshot_name" = 'plist' ]; then validate_plist_target "$artifact"; fi
                        ;;
                    *) return 1 ;;
                esac
            }
            delete_rollback_artifacts() {
                validate_rollback_artifacts
                for snapshot_name in configuration plist; do
                    for suffix in link file missing; do
                        artifact="$rollback/$snapshot_name.$suffix"
                        if [ -f "$artifact" ]; then
                            validate_managed_directory "$rollback_parent"
                            validate_private_directory "$rollback"
                            validate_artifact_for_delete "$artifact" "$snapshot_name" "$suffix"
                            /bin/rm -- "$artifact"
                        fi
                    done
                done
                validate_managed_directory "$rollback_parent"
                validate_private_directory "$rollback"
                /bin/rmdir -- "$rollback"
            }
            BASH;
    }

    /**
     * @param array{user_id: string, loaded: bool, running: bool} $state
     * @param array{lock_path: string, token: string} $lease
     * @mago-expect lint:sensitive-parameter The random publication token is an identifier, not a credential.
     */
    private function restorePublishedState(
        Node $node,
        string $home,
        string $label,
        string $plist,
        string $token,
        array $state,
        array $lease,
    ): void {
        $rollbackFailure = null;

        try {
            $this->rollback($node, $home, $plist, $token);
        } catch (Throwable $caught) {
            $rollbackFailure = $caught;
        }

        try {
            $this->launchAgents->restore($node, $label, $plist, $state, $lease);
        } catch (Throwable $caught) {
            $rollbackFailure ??= $caught;
        }

        if ($rollbackFailure !== null) {
            throw new RuntimeConvergenceException(
                step: 'caddy-rollback',
                errorCode: 'app-dev.caddy_rollback_failed',
                message: 'The macOS Caddy rollback failed.',
            );
        }
    }

    /** @mago-expect lint:sensitive-parameter The random publication token is an identifier, not a credential. */
    private function rollback(Node $node, string $home, string $plist, string $token): void
    {
        $live = $this->layout->caddyCurrent($home);
        $rollback = "{$home}/.orbit/run/.caddy-rollback-{$token}";
        $lockPath = $this->layout->caddyLock($home);
        $result = $this->execute($node, new RemoteCommand(
            arguments: ['/bin/bash', '-seu', '--', $live, $plist, $rollback, $lockPath, $token],
            input: <<<'BASH'
                live_configuration=$1; plist=$2; rollback=$3; lock_path=$4; token=$5
                expected_user=$(/usr/bin/id -un)
                expected_label='com.orbit.caddy'
                caddy_root=$(/usr/bin/dirname "$live_configuration")
                live_parent=$(/usr/bin/dirname "$live_configuration")
                plist_parent=$(/usr/bin/dirname "$plist")
                rollback_parent=$(/usr/bin/dirname "$rollback")
                published_directory="$caddy_root/versions/$token"
                test -d "$lock_path"; test ! -L "$lock_path"
                test "$(cd "$lock_path" && pwd -P)" = "$lock_path"
                test -f "$lock_path/owner"; test ! -L "$lock_path/owner"
                test "$(/usr/bin/wc -l < "$lock_path/owner" | tr -d ' ')" = 1
                read -r current_token keeper_pid extra < "$lock_path/owner"
                test -z "${extra:-}"; test "$current_token" = "$token"
                case "$keeper_pid" in ''|*[!0-9]*) exit 76 ;; esac
                kill -0 "$keeper_pid" 2>/dev/null
                keeper_command=$(/bin/ps -ww -p "$keeper_pid" -o command=)
                case "$keeper_command" in *"orbit-lease-keeper $token $lock_path") ;; *) exit 76 ;; esac

                validate_managed_directory() {
                    managed_directory=$1
                    test -d "$managed_directory"; test ! -L "$managed_directory"
                    test "$(cd "$managed_directory" && pwd -P)" = "$managed_directory"
                    test "$(/usr/bin/stat -f '%Su' "$managed_directory")" = "$expected_user"
                }
                validate_artifact() {
                    artifact=$1
                    test -f "$artifact"; test ! -L "$artifact"
                    test "$(/usr/bin/stat -f '%Su' "$artifact")" = "$expected_user"
                    artifact_mode=$(/usr/bin/stat -f '%Lp' "$artifact")
                    case "$artifact" in
                        *.file) case "$artifact_mode" in 600|644) ;; *) return 1 ;; esac ;;
                        *) test "$artifact_mode" = '600' ;;
                    esac
                }
                validate_rollback_artifacts() {
                    validate_managed_directory "$rollback_parent"
                    test -d "$rollback"; test ! -L "$rollback"
                    test "$(cd "$rollback" && pwd -P)" = "$rollback"
                    test "$(/usr/bin/stat -f '%Su' "$rollback")" = "$expected_user"
                    test "$(/usr/bin/stat -f '%Lp' "$rollback")" = '700'
                    for snapshot_name in configuration plist; do
                        marker_count=0
                        for suffix in link file missing; do
                            artifact="$rollback/$snapshot_name.$suffix"
                            if [ -e "$artifact" ] || [ -L "$artifact" ]; then
                                marker_count=$((marker_count + 1))
                                validate_artifact "$artifact"
                                if [ "$suffix" = 'missing' ]; then test ! -s "$artifact"; fi
                                if [ "$suffix" = 'link' ]; then
                                    test "$(/usr/bin/wc -l < "$artifact" | /usr/bin/tr -d ' ')" = 1
                                    test -n "$(/bin/cat "$artifact")"
                                fi
                            fi
                        done
                        test "$marker_count" = 1
                    done
                    for artifact in "$rollback"/*; do
                        case "$(/usr/bin/basename "$artifact")" in
                            configuration.link|configuration.file|configuration.missing|plist.link|plist.file|plist.missing) ;;
                            *) return 1 ;;
                        esac
                    done
                    if [ -f "$rollback/plist.file" ]; then
                        test "$(/usr/bin/plutil -extract Label raw -o - "$rollback/plist.file")" = "$expected_label"
                    fi
                    if [ -f "$rollback/plist.link" ]; then
                        linked_plist_target=$(/bin/cat "$rollback/plist.link")
                        case "$linked_plist_target" in
                            /*) linked_plist="$linked_plist_target" ;;
                            *) linked_plist="$plist_parent/$linked_plist_target" ;;
                        esac
                        test -f "$linked_plist"; test ! -L "$linked_plist"
                        test "$(/usr/bin/stat -f '%Su' "$linked_plist")" = "$expected_user"
                        case "$(/usr/bin/stat -f '%Lp' "$linked_plist")" in 600|644) ;; *) return 1 ;; esac
                        test "$(/usr/bin/plutil -extract Label raw -o - "$linked_plist")" = "$expected_label"
                    fi
                }
                path_matches_snapshot() {
                    path=$1; name=$2
                    if [ -f "$rollback/$name.link" ]; then
                        [ -L "$path" ] \
                            && [ "$(/usr/bin/stat -f '%Su' "$path")" = "$expected_user" ] \
                            && [ "$(/usr/bin/readlink "$path")" = "$(/bin/cat "$rollback/$name.link")" ]
                    elif [ -f "$rollback/$name.file" ]; then
                        [ -f "$path" ] && [ ! -L "$path" ] \
                            && [ "$(/usr/bin/stat -f '%Su' "$path")" = "$expected_user" ] \
                            && [ "$(/usr/bin/stat -f '%Lp' "$path")" = "$(/usr/bin/stat -f '%Lp' "$rollback/$name.file")" ] \
                            && /usr/bin/cmp -s -- "$path" "$rollback/$name.file"
                    else
                        test -f "$rollback/$name.missing" \
                            && [ ! -e "$path" ] && [ ! -L "$path" ]
                    fi
                }
                validate_current_publication() {
                    path=$1; name=$2
                    if [ "$name" = 'configuration' ]; then
                        test -L "$path"
                        test "$(/usr/bin/stat -f '%Su' "$path")" = "$expected_user"
                        test "$(/usr/bin/readlink "$path")" = "$published_directory/Caddyfile"
                        return
                    fi
                    published_plist="$published_directory/$(/usr/bin/basename "$plist")"
                    test -f "$path"; test ! -L "$path"
                    test -f "$published_plist"; test ! -L "$published_plist"
                    test "$(/usr/bin/stat -f '%Su' "$path")" = "$expected_user"
                    test "$(/usr/bin/stat -f '%Lp' "$path")" = '600'
                    test "$(/usr/bin/plutil -extract Label raw -o - "$path")" = "$expected_label"
                    /usr/bin/cmp -s -- "$path" "$published_plist"
                }
                validate_restore_candidate() {
                    restore_candidate=$1; name=$2
                    if [ -f "$rollback/$name.link" ]; then
                        test -L "$restore_candidate"
                        test "$(/usr/bin/stat -f '%Su' "$restore_candidate")" = "$expected_user"
                        test "$(/usr/bin/readlink "$restore_candidate")" = "$(/bin/cat "$rollback/$name.link")"
                        if [ "$name" = 'plist' ]; then
                            linked_plist_target=$(/usr/bin/readlink "$restore_candidate")
                            case "$linked_plist_target" in
                                /*) linked_plist="$linked_plist_target" ;;
                                *) linked_plist="$plist_parent/$linked_plist_target" ;;
                            esac
                            test -f "$linked_plist"; test ! -L "$linked_plist"
                            test "$(/usr/bin/stat -f '%Su' "$linked_plist")" = "$expected_user"
                            case "$(/usr/bin/stat -f '%Lp' "$linked_plist")" in 600|644) ;; *) return 1 ;; esac
                            test "$(/usr/bin/plutil -extract Label raw -o - "$linked_plist")" = "$expected_label"
                        fi
                    else
                        test -f "$restore_candidate"; test ! -L "$restore_candidate"
                        test "$(/usr/bin/stat -f '%Su' "$restore_candidate")" = "$expected_user"
                        test "$(/usr/bin/stat -f '%Lp' "$restore_candidate")" = "$(/usr/bin/stat -f '%Lp' "$rollback/$name.file")"
                        /usr/bin/cmp -s -- "$restore_candidate" "$rollback/$name.file"
                        if [ "$name" = 'plist' ]; then
                            test "$(/usr/bin/plutil -extract Label raw -o - "$restore_candidate")" = "$expected_label"
                        fi
                    fi
                }
                validate_restore_directory() {
                    test -d "$restore_directory"; test ! -L "$restore_directory"
                    test "$(cd "$restore_directory" && pwd -P)" = "$restore_directory"
                    test "$(/usr/bin/stat -f '%Su' "$restore_directory")" = "$expected_user"
                    test "$(/usr/bin/stat -f '%Lp' "$restore_directory")" = '700'
                }
                stage_restore_candidate() {
                    path=$1; name=$2
                    if [ -f "$rollback/$name.missing" ]; then
                        restore_directory=''
                        restore_candidate=''
                        return
                    fi
                    restore_parent=$(/usr/bin/dirname "$path")
                    validate_managed_directory "$restore_parent"
                    restore_directory="$restore_parent/.orbit-restore-$token-$name"
                    if ! /bin/mkdir -m 0700 -- "$restore_directory"; then return 1; fi
                    validate_restore_directory
                    restore_candidate="$restore_directory/restored"
                    if [ -f "$rollback/$name.link" ]; then
                        /bin/ln -s -- "$(/bin/cat "$rollback/$name.link")" "$restore_candidate"
                    elif [ -f "$rollback/$name.file" ]; then
                        /bin/cp -p -- "$rollback/$name.file" "$restore_candidate"
                    else
                        return 1
                    fi
                    validate_restore_directory
                    validate_restore_candidate "$restore_candidate" "$name"
                }
                restore_path() {
                    path=$1; name=$2
                    if path_matches_snapshot "$path" "$name"; then return; fi
                    stage_restore_candidate "$path" "$name"
                    validate_rollback_artifacts
                    if [ "$name" = 'configuration' ]; then
                        validate_managed_directory "$live_parent"
                    else
                        validate_managed_directory "$plist_parent"
                    fi
                    validate_current_publication "$path" "$name"
                    if [ -n "$restore_candidate" ]; then
                        validate_restore_directory
                        validate_restore_candidate "$restore_candidate" "$name"
                        /bin/mv -h -f -- "$restore_candidate" "$path"
                        validate_restore_directory
                        /bin/rmdir -- "$restore_directory"
                    else
                        validate_artifact "$rollback/$name.missing"
                        /bin/rm -f -- "$path"
                    fi
                    path_matches_snapshot "$path" "$name"
                }
                validate_artifact_for_delete() {
                    artifact=$1; snapshot_name=$2; suffix=$3
                    validate_artifact "$artifact"
                    case "$suffix" in
                        missing) test ! -s "$artifact" ;;
                        link)
                            test "$(/usr/bin/wc -l < "$artifact" | /usr/bin/tr -d ' ')" = 1
                            link_target=$(/bin/cat "$artifact")
                            test -n "$link_target"
                            if [ "$snapshot_name" = 'plist' ]; then
                                case "$link_target" in
                                    /*) linked_plist="$link_target" ;;
                                    *) linked_plist="$plist_parent/$link_target" ;;
                                esac
                                test -f "$linked_plist"; test ! -L "$linked_plist"
                                test "$(/usr/bin/stat -f '%Su' "$linked_plist")" = "$expected_user"
                                case "$(/usr/bin/stat -f '%Lp' "$linked_plist")" in 600|644) ;; *) return 1 ;; esac
                                test "$(/usr/bin/plutil -extract Label raw -o - "$linked_plist")" = "$expected_label"
                            fi
                            ;;
                        file)
                            if [ "$snapshot_name" = 'plist' ]; then
                                test "$(/usr/bin/plutil -extract Label raw -o - "$artifact")" = "$expected_label"
                            fi
                            ;;
                        *) return 1 ;;
                    esac
                }
                delete_rollback_artifacts() {
                    validate_rollback_artifacts
                    for snapshot_name in configuration plist; do
                        for suffix in link file missing; do
                            artifact="$rollback/$snapshot_name.$suffix"
                            if [ -f "$artifact" ]; then
                                validate_managed_directory "$rollback_parent"
                                test -d "$rollback"; test ! -L "$rollback"
                                validate_artifact_for_delete "$artifact" "$snapshot_name" "$suffix"
                                /bin/rm -- "$artifact"
                            fi
                        done
                    done
                    validate_managed_directory "$rollback_parent"
                    test -d "$rollback"; test ! -L "$rollback"
                    test "$(/usr/bin/stat -f '%Su' "$rollback")" = "$expected_user"
                    test "$(/usr/bin/stat -f '%Lp' "$rollback")" = '700'
                    /bin/rmdir -- "$rollback"
                }
                validate_managed_directory "$live_parent"
                validate_managed_directory "$plist_parent"
                validate_rollback_artifacts
                restore_path "$live_configuration" configuration
                restore_path "$plist" plist
                path_matches_snapshot "$live_configuration" configuration
                path_matches_snapshot "$plist" plist
                delete_rollback_artifacts
                BASH,
        ));

        if (! $result->succeeded()) {
            throw $this->failure('caddy-rollback', 'app-dev.caddy_rollback_failed', $result);
        }
    }

    /** @mago-expect lint:sensitive-parameter The random publication token is an identifier, not a credential. */
    private function cleanup(Node $node, string $home, string $token): void
    {
        $rollback = "{$home}/.orbit/run/.caddy-rollback-{$token}";
        $lockPath = $this->layout->caddyLock($home);
        $result = $this->execute($node, new RemoteCommand(
            arguments: ['/bin/bash', '-seu', '--', $rollback, $lockPath, $token],
            input: <<<'BASH'
                rollback=$1; lock_path=$2; token=$3
                expected_user=$(/usr/bin/id -un)
                expected_label='com.orbit.caddy'
                home=${lock_path%/.orbit/run/caddy.lock}
                test "$lock_path" = "$home/.orbit/run/caddy.lock"
                plist_parent="$home/Library/LaunchAgents"
                rollback_parent=$(/usr/bin/dirname "$rollback")
                test -d "$lock_path"; test ! -L "$lock_path"
                test "$(cd "$lock_path" && pwd -P)" = "$lock_path"
                test -f "$lock_path/owner"; test ! -L "$lock_path/owner"
                test "$(/usr/bin/wc -l < "$lock_path/owner" | tr -d ' ')" = 1
                read -r current_token keeper_pid extra < "$lock_path/owner"
                test -z "${extra:-}"; test "$current_token" = "$token"
                case "$keeper_pid" in ''|*[!0-9]*) exit 76 ;; esac
                kill -0 "$keeper_pid" 2>/dev/null
                keeper_command=$(/bin/ps -ww -p "$keeper_pid" -o command=)
                case "$keeper_command" in *"orbit-lease-keeper $token $lock_path") ;; *) exit 76 ;; esac
                validate_managed_directory() {
                    managed_directory=$1
                    test -d "$managed_directory"; test ! -L "$managed_directory"
                    test "$(cd "$managed_directory" && pwd -P)" = "$managed_directory"
                    test "$(/usr/bin/stat -f '%Su' "$managed_directory")" = "$expected_user"
                }
                validate_artifact() {
                    artifact=$1
                    test -f "$artifact"; test ! -L "$artifact"
                    test "$(/usr/bin/stat -f '%Su' "$artifact")" = "$expected_user"
                    artifact_mode=$(/usr/bin/stat -f '%Lp' "$artifact")
                    case "$artifact" in
                        *.file) case "$artifact_mode" in 600|644) ;; *) return 1 ;; esac ;;
                        *) test "$artifact_mode" = '600' ;;
                    esac
                }
                validate_rollback_artifacts() {
                    validate_managed_directory "$rollback_parent"
                    test -d "$rollback"; test ! -L "$rollback"
                    test "$(cd "$rollback" && pwd -P)" = "$rollback"
                    test "$(/usr/bin/stat -f '%Su' "$rollback")" = "$expected_user"
                    test "$(/usr/bin/stat -f '%Lp' "$rollback")" = '700'
                    for snapshot_name in configuration plist; do
                        marker_count=0
                        for suffix in link file missing; do
                            artifact="$rollback/$snapshot_name.$suffix"
                            if [ -e "$artifact" ] || [ -L "$artifact" ]; then
                                marker_count=$((marker_count + 1))
                                validate_artifact "$artifact"
                                if [ "$suffix" = 'missing' ]; then test ! -s "$artifact"; fi
                                if [ "$suffix" = 'link' ]; then
                                    test "$(/usr/bin/wc -l < "$artifact" | /usr/bin/tr -d ' ')" = 1
                                    test -n "$(/bin/cat "$artifact")"
                                fi
                            fi
                        done
                        test "$marker_count" = 1
                    done
                    for artifact in "$rollback"/*; do
                        case "$(/usr/bin/basename "$artifact")" in
                            configuration.link|configuration.file|configuration.missing|plist.link|plist.file|plist.missing) ;;
                            *) return 1 ;;
                        esac
                        validate_artifact "$artifact"
                    done
                    if [ -f "$rollback/plist.file" ]; then
                        test "$(/usr/bin/plutil -extract Label raw -o - "$rollback/plist.file")" = "$expected_label"
                    fi
                    if [ -f "$rollback/plist.link" ]; then
                        linked_plist_target=$(/bin/cat "$rollback/plist.link")
                        case "$linked_plist_target" in
                            /*) linked_plist="$linked_plist_target" ;;
                            *) linked_plist="$plist_parent/$linked_plist_target" ;;
                        esac
                        test -f "$linked_plist"; test ! -L "$linked_plist"
                        test "$(/usr/bin/stat -f '%Su' "$linked_plist")" = "$expected_user"
                        case "$(/usr/bin/stat -f '%Lp' "$linked_plist")" in 600|644) ;; *) return 1 ;; esac
                        test "$(/usr/bin/plutil -extract Label raw -o - "$linked_plist")" = "$expected_label"
                    fi
                }
                validate_artifact_for_delete() {
                    artifact=$1; snapshot_name=$2; suffix=$3
                    validate_artifact "$artifact"
                    case "$suffix" in
                        missing) test ! -s "$artifact" ;;
                        link)
                            test "$(/usr/bin/wc -l < "$artifact" | /usr/bin/tr -d ' ')" = 1
                            link_target=$(/bin/cat "$artifact")
                            test -n "$link_target"
                            if [ "$snapshot_name" = 'plist' ]; then
                                case "$link_target" in
                                    /*) linked_plist="$link_target" ;;
                                    *) linked_plist="$plist_parent/$link_target" ;;
                                esac
                                test -f "$linked_plist"; test ! -L "$linked_plist"
                                test "$(/usr/bin/stat -f '%Su' "$linked_plist")" = "$expected_user"
                                case "$(/usr/bin/stat -f '%Lp' "$linked_plist")" in 600|644) ;; *) return 1 ;; esac
                                test "$(/usr/bin/plutil -extract Label raw -o - "$linked_plist")" = "$expected_label"
                            fi
                            ;;
                        file)
                            if [ "$snapshot_name" = 'plist' ]; then
                                test "$(/usr/bin/plutil -extract Label raw -o - "$artifact")" = "$expected_label"
                            fi
                            ;;
                        *) return 1 ;;
                    esac
                }
                delete_rollback_artifacts() {
                    validate_rollback_artifacts
                    for snapshot_name in configuration plist; do
                        for suffix in link file missing; do
                            artifact="$rollback/$snapshot_name.$suffix"
                            if [ -f "$artifact" ]; then
                                validate_managed_directory "$rollback_parent"
                                test -d "$rollback"; test ! -L "$rollback"
                                validate_artifact_for_delete "$artifact" "$snapshot_name" "$suffix"
                                /bin/rm -- "$artifact"
                            fi
                        done
                    done
                    validate_managed_directory "$rollback_parent"
                    test -d "$rollback"; test ! -L "$rollback"
                    test "$(/usr/bin/stat -f '%Su' "$rollback")" = "$expected_user"
                    test "$(/usr/bin/stat -f '%Lp' "$rollback")" = '700'
                    /bin/rmdir -- "$rollback"
                }
                if [ -e "$rollback" ] || [ -L "$rollback" ]; then
                    validate_managed_directory "$rollback_parent"
                    delete_rollback_artifacts
                fi
                BASH,
        ));

        if (! $result->succeeded()) {
            throw $this->failure('caddy-cleanup', 'app-dev.caddy_cleanup_failed', $result);
        }
    }

    private function execute(Node $node, RemoteCommand $command): CommandResult
    {
        return $this->ssh->execute($this->connections->make($node), $this->guard->guard($command));
    }

    private function caddyBinary(Node $node): string
    {
        return match ($node->architecture) {
            'arm64' => '/opt/homebrew/opt/caddy/bin/caddy',
            'x86_64' => '/usr/local/opt/caddy/bin/caddy',
            default => throw new RuntimeConvergenceException(
                step: 'caddy-config',
                errorCode: 'app-dev.caddy_architecture_unsupported',
                message: 'The Darwin Caddy architecture is not supported.',
            ),
        };
    }

    private function plist(Node $node, string $caddy, string $home): string
    {
        $configuration = $this->layout->caddyCurrent($home);
        $log = $this->layout->caddyLog($home);
        $prefix = $node->architecture === 'arm64' ? '/opt/homebrew' : '/usr/local';

        return <<<XML
            <?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
            <plist version="1.0"><dict>
            <key>Label</key><string>com.orbit.caddy</string>
            <key>ProgramArguments</key><array><string>{$caddy}</string><string>run</string><string>--config</string><string>{$configuration}</string><string>--adapter</string><string>caddyfile</string></array>
            <key>EnvironmentVariables</key><dict><key>HOME</key><string>{$home}</string><key>USER</key><string>{$node->ssh_user}</string><key>PATH</key><string>{$prefix}/bin:{$prefix}/sbin:/usr/bin:/bin:/usr/sbin:/sbin</string></dict>
            <key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
            <key>StandardOutPath</key><string>{$log}</string><key>StandardErrorPath</key><string>{$log}</string>
            </dict></plist>
            XML;
    }

    private function failure(string $step, string $errorCode, CommandResult $result): RuntimeConvergenceException
    {
        return new RuntimeConvergenceException(
            step: $step,
            errorCode: $errorCode,
            message: 'The macOS Caddy operation failed.',
            result: $result,
        );
    }
}
