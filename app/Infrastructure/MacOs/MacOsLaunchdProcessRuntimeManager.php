<?php

declare(strict_types=1);

namespace App\Infrastructure\MacOs;

use App\Domain\Processes\DesiredProcessState;
use App\Domain\Processes\ProcessOperationException;
use App\Domain\Processes\ProcessRuntimeManager;
use App\Domain\Processes\ProcessTarget;
use App\Domain\Processes\ProcessTargetResolver;
use App\Domain\Shared\ResourceOperationException;
use App\Infrastructure\Activity\CommandActivityInputSanitizer;
use App\Infrastructure\Processes\CommandResult;
use App\Infrastructure\Processes\LaunchdProcessRenderer;
use App\Infrastructure\Processes\ProtectedInput;
use App\Infrastructure\Ssh\RemoteCommand;
use App\Infrastructure\Ssh\SshConnection;
use App\Infrastructure\Ssh\SshExecutor;
use App\Models\Process;
use Illuminate\Support\Facades\Cache;
use SensitiveParameter;
use Throwable;

/**
 * @mago-expect lint:cyclomatic-complexity Launchd runtime convergence keeps publication, activation, and recovery together.
 * @mago-expect lint:kan-defect The score reflects explicit publication, activation, and recovery gates.
 * @mago-expect lint:too-many-methods Public lifecycle methods and recovery helpers form one runtime boundary.
 */
final readonly class MacOsLaunchdProcessRuntimeManager implements ProcessRuntimeManager
{
    private const float START_READINESS_TIMEOUT_SECONDS = 15.0;

    private const int START_READINESS_POLL_MICROSECONDS = 500_000;

    private const string PATH_CHECK_SCRIPT = <<<'BASH'
        expected_user=$1
        label=$2
        prepare_logs=$3
        home=$4
        orbit_home=$5
        library=$6
        launch_agents=$7
        logs=$8
        orbit_logs=$9
        process_logs=${10}
        plist=${11}
        stdout=${12}
        stderr=${13}
        candidate="$launch_agents/.$label.candidate.plist"
        backup="$launch_agents/.$label.rollback.plist"

        fail() { exit 73; }
        validate_directory() {
            path=$1
            test -d "$path" || fail
            test ! -L "$path" || fail
            test "$(cd "$path" && /bin/pwd -P)" = "$path" || fail
            test "$(/usr/bin/stat -f %Su -- "$path")" = "$expected_user" || fail
        }
        prepare_directory() {
            parent=$1
            path=$2
            validate_directory "$parent"
            if test -L "$path"; then fail; fi
            if ! test -e "$path"; then
                test "$prepare_logs" = 1 || return 0
                /bin/mkdir "$path"
            fi
            validate_directory "$path"
        }
        validate_file_if_present() {
            path=$1
            if test -L "$path"; then fail; fi
            if ! test -e "$path"; then return 0; fi
            test -f "$path" || fail
            test "$(/usr/bin/stat -f %Su -- "$path")" = "$expected_user" || fail
            test "$(/usr/bin/stat -f %Lp -- "$path")" = 600 || fail
        }
        validate_label_if_present() {
            path=$1
            if ! test -e "$path"; then return 0; fi
            observed_label=$(/usr/bin/plutil -extract Label raw -o - -- "$path") || fail
            test "$observed_label" = "$label" || fail
        }

        validate_directory "$home"
        validate_directory "$orbit_home"
        validate_directory "$library"
        validate_directory "$launch_agents"
        prepare_directory "$library" "$logs"
        prepare_directory "$logs" "$orbit_logs"
        prepare_directory "$orbit_logs" "$process_logs"
        validate_file_if_present "$plist"
        validate_file_if_present "$stdout"
        validate_file_if_present "$stderr"
        validate_file_if_present "$candidate"
        validate_file_if_present "$backup"
        validate_label_if_present "$plist"
        validate_label_if_present "$candidate"
        validate_label_if_present "$backup"
        BASH;

    private const string PUBLISH_SCRIPT = <<<'BASH'
        umask 077
        expected_user=$1
        label=$2
        plist=$3
        stdout=$4
        stderr=$5
        directory=${plist%/*}
        candidate="$directory/.$label.candidate.plist"
        backup="$directory/.$label.rollback.plist"
        had_backup=0
        published=0
        candidate_created=0

        fail() { exit 73; }
        validate_directory() {
            path=$1
            test -d "$path" || fail
            test ! -L "$path" || fail
            test "$(cd "$path" && /bin/pwd -P)" = "$path" || fail
            test "$(/usr/bin/stat -f %Su -- "$path")" = "$expected_user" || fail
        }
        validate_file_if_present() {
            path=$1
            if test -L "$path"; then fail; fi
            if ! test -e "$path"; then return 0; fi
            test -f "$path" || fail
            test "$(/usr/bin/stat -f %Su -- "$path")" = "$expected_user" || fail
            test "$(/usr/bin/stat -f %Lp -- "$path")" = 600 || fail
        }
        validate_label_if_present() {
            path=$1
            if ! test -e "$path"; then return 0; fi
            observed_label=$(/usr/bin/plutil -extract Label raw -o - -- "$path") || fail
            test "$observed_label" = "$label" || fail
        }
        cleanup() {
            exit_code=$?
            if test "$candidate_created" = 1 && test -e "$candidate"; then
                validate_file_if_present "$candidate"
                validate_label_if_present "$candidate"
                /bin/rm -f -- "$candidate"
            fi
            if test "$had_backup" = 1 && test "$published" = 0; then
                validate_file_if_present "$backup"
                validate_label_if_present "$backup"
                /bin/rm -f -- "$backup"
            fi
            exit "$exit_code"
        }
        trap cleanup EXIT HUP INT TERM

        validate_directory "$directory"
        validate_directory "${stdout%/*}"
        validate_file_if_present "$plist"
        validate_file_if_present "$stdout"
        validate_file_if_present "$stderr"
        validate_file_if_present "$candidate"
        validate_file_if_present "$backup"
        validate_label_if_present "$plist"
        validate_label_if_present "$candidate"
        validate_label_if_present "$backup"
        test ! -e "$candidate" || exit 75
        test ! -e "$backup" || exit 75

        candidate_created=1
        /bin/cat > "$candidate"
        /bin/chmod 0600 "$candidate"
        /usr/bin/plutil -lint "$candidate" >/dev/null
        validate_file_if_present "$candidate"
        validate_label_if_present "$candidate"
        /usr/bin/touch "$stdout" "$stderr"
        /bin/chmod 0600 "$stdout" "$stderr"

        if test -e "$plist"; then
            validate_file_if_present "$plist"
            validate_label_if_present "$plist"
            /bin/cp -p "$plist" "$backup"
            /bin/chmod 0600 "$backup"
            validate_file_if_present "$backup"
            validate_label_if_present "$backup"
            had_backup=1
        fi

        validate_directory "$directory"
        validate_file_if_present "$plist"
        validate_file_if_present "$candidate"
        validate_label_if_present "$plist"
        validate_label_if_present "$candidate"
        /bin/mv -f -- "$candidate" "$plist"
        published=1
        trap - EXIT HUP INT TERM
        BASH;

    private const string ROLLBACK_SCRIPT = <<<'BASH'
        expected_user=$1
        label=$2
        gui=$3
        plist=$4
        existed=$5
        was_loaded=$6
        was_running=$7
        directory=${plist%/*}
        candidate="$directory/.$label.candidate.plist"
        backup="$directory/.$label.rollback.plist"
        service="$gui/$label"

        fail() { exit 73; }
        validate_directory() {
            path=$1
            test -d "$path" || fail
            test ! -L "$path" || fail
            test "$(cd "$path" && /bin/pwd -P)" = "$path" || fail
            test "$(/usr/bin/stat -f %Su -- "$path")" = "$expected_user" || fail
        }
        validate_file_if_present() {
            path=$1
            if test -L "$path"; then fail; fi
            if ! test -e "$path"; then return 0; fi
            test -f "$path" || fail
            test "$(/usr/bin/stat -f %Su -- "$path")" = "$expected_user" || fail
            test "$(/usr/bin/stat -f %Lp -- "$path")" = 600 || fail
        }
        validate_label_if_present() {
            path=$1
            if ! test -e "$path"; then return 0; fi
            observed_label=$(/usr/bin/plutil -extract Label raw -o - -- "$path") || fail
            test "$observed_label" = "$label" || fail
        }
        bootout_tolerating_native_absence() {
            output=$(/bin/launchctl bootout "$service" 2>&1) && return 0
            canonical="Could not find service \"$label\" in domain for user gui: ${gui#gui/}"
            prefixed=$(printf 'Bad request.\n%s' "$canonical")
            if test "$output" = "$canonical" || test "$output" = "$prefixed"; then
                return 0
            fi
            case "$output" in
                'Could not find service'|'service could not be found'|'No such process'|'Boot-out failed: 3: No such process') return 0 ;;
                *) return 1 ;;
            esac
        }

        validate_directory "$directory"
        validate_file_if_present "$plist"
        validate_file_if_present "$candidate"
        validate_file_if_present "$backup"
        validate_label_if_present "$plist"
        validate_label_if_present "$candidate"
        validate_label_if_present "$backup"
        bootout_tolerating_native_absence

        if test "$existed" = 1; then
            test -f "$backup" || fail
            validate_file_if_present "$plist"
            validate_file_if_present "$backup"
            validate_label_if_present "$plist"
            validate_label_if_present "$backup"
            /bin/mv -f -- "$backup" "$plist"
            validate_file_if_present "$plist"
            validate_label_if_present "$plist"
        else
            if test -e "$plist"; then
                validate_file_if_present "$plist"
                validate_label_if_present "$plist"
                /bin/rm -f -- "$plist"
            fi
            if test -e "$backup"; then
                validate_file_if_present "$backup"
                validate_label_if_present "$backup"
                /bin/rm -f -- "$backup"
            fi
        fi
        if test -e "$candidate"; then
            validate_file_if_present "$candidate"
            validate_label_if_present "$candidate"
            /bin/rm -f -- "$candidate"
        fi

        if test "$was_loaded" = 0; then
            /bin/launchctl disable "$service"
            exit 0
        fi

        if test "$was_running" = 1; then
            /bin/launchctl enable "$service"
        else
            /bin/launchctl disable "$service"
        fi
        /bin/launchctl bootstrap "$gui" "$plist"
        if test "$was_running" = 1; then
            /bin/launchctl kickstart -k "$service"
            /bin/launchctl print "$service" | /usr/bin/grep -Eq '^[[:space:]]*state[[:space:]]*=[[:space:]]*running[[:space:]]*$'
        else
            /bin/launchctl stop "$service"
            status=$(/bin/launchctl print "$service")
            printf '%s\n' "$status" | /usr/bin/grep -Eq '^[[:space:]]*state[[:space:]]*=[[:space:]]*not running[[:space:]]*$'
        fi
        BASH;

    private const string CLEANUP_SCRIPT = <<<'BASH'
        expected_user=$1
        label=$2
        plist=$3
        directory=${plist%/*}
        candidate="$directory/.$label.candidate.plist"
        backup="$directory/.$label.rollback.plist"
        fail() { exit 73; }
        validate_directory() {
            path=$1
            test -d "$path" || fail
            test ! -L "$path" || fail
            test "$(cd "$path" && /bin/pwd -P)" = "$path" || fail
            test "$(/usr/bin/stat -f %Su -- "$path")" = "$expected_user" || fail
        }
        validate_label_if_present() {
            path=$1
            if ! test -e "$path"; then return 0; fi
            observed_label=$(/usr/bin/plutil -extract Label raw -o - -- "$path") || fail
            test "$observed_label" = "$label" || fail
        }
        validate_directory "$directory"
        for path in "$candidate" "$backup"; do
            if test -L "$path"; then fail; fi
            if ! test -e "$path"; then continue; fi
            test -f "$path" || fail
            test "$(/usr/bin/stat -f %Su -- "$path")" = "$expected_user" || fail
            test "$(/usr/bin/stat -f %Lp -- "$path")" = 600 || fail
            validate_label_if_present "$path"
            /bin/rm -f -- "$path"
        done
        BASH;

    private const string REMOVE_SCRIPT = <<<'BASH'
        expected_user=$1
        label=$2
        plist=$3
        stdout=$4
        stderr=$5
        directory=${plist%/*}
        candidate="$directory/.$label.candidate.plist"
        backup="$directory/.$label.rollback.plist"
        fail() { exit 73; }
        validate_directory() {
            path=$1
            test -d "$path" || fail
            test ! -L "$path" || fail
            test "$(cd "$path" && /bin/pwd -P)" = "$path" || fail
            test "$(/usr/bin/stat -f %Su -- "$path")" = "$expected_user" || fail
        }
        validate_label_if_present() {
            path=$1
            if ! test -e "$path"; then return 0; fi
            observed_label=$(/usr/bin/plutil -extract Label raw -o - -- "$path") || fail
            test "$observed_label" = "$label" || fail
        }
        validate_directory "$directory"
        validate_directory "${stdout%/*}"
        validate_directory "${stderr%/*}"
        for path in "$plist" "$stdout" "$stderr" "$candidate" "$backup"; do
            if test -L "$path"; then fail; fi
            if ! test -e "$path"; then continue; fi
            test -f "$path" || fail
            test "$(/usr/bin/stat -f %Su -- "$path")" = "$expected_user" || fail
            test "$(/usr/bin/stat -f %Lp -- "$path")" = 600 || fail
        done
        validate_label_if_present "$plist"
        validate_label_if_present "$candidate"
        validate_label_if_present "$backup"
        /bin/rm -f -- "$plist" "$stdout" "$stderr" "$candidate" "$backup"
        BASH;

    /** @mago-expect lint:excessive-parameter-list Runtime wiring needs the SSH and rendering boundaries explicitly. */
    public function __construct(
        private ProcessTargetResolver $targets,
        private MacOsSshConnectionFactory $connections,
        private SshExecutor $ssh,
        private MacOsSteadyStateCommandGuard $guard,
        private LaunchdProcessRenderer $renderer,
        private CommandActivityInputSanitizer $sanitizer = new CommandActivityInputSanitizer,
        private ?int $startReadinessAttempts = null,
        private float $startReadinessTimeoutSeconds = self::START_READINESS_TIMEOUT_SECONDS,
        private int $startReadinessPollMicroseconds = self::START_READINESS_POLL_MICROSECONDS,
    ) {}

    /** @mago-expect lint:halstead Convergence preserves the ordered publication, activation, and recovery contract. */
    public function converge(#[SensitiveParameter] Process $process): void
    {
        /** @mago-expect lint:halstead The locked operation keeps its snapshot and pinned connection in one scope. */
        $this->withRuntimeLock($process, function (ProcessTarget $target, SshConnection $connection) use (
            $process,
        ): void {
            $session = $this->userSession($process, $connection);
            $paths = $this->paths($process, $target);
            $this->assertSafePaths($process, $connection, $target, $paths, prepareLogs: true);
            $snapshot = $this->snapshot($process, $connection, $session['uid'], $paths['label'], $paths['plist']);
            $candidate = ProtectedInput::fromString($this->renderer->render($process, $target));

            try {
                $publish = $this->execute($process, $connection, new RemoteCommand(
                    arguments: [
                        '/bin/bash',
                        '-seu',
                        '-c',
                        self::PUBLISH_SCRIPT,
                        'orbit-launchd-publish',
                        $target->user,
                        $paths['label'],
                        $paths['plist'],
                        $paths['stdout'],
                        $paths['stderr'],
                    ],
                    protectedInput: $candidate,
                ));
            } catch (Throwable) {
                $this->restoreSnapshot($process, $connection, $target, $session['uid'], $paths, $snapshot);

                throw new ProcessOperationException(
                    step: 'publish-launchd-state',
                    errorCode: 'process.launchd_converge_failed',
                    message: 'The launchd publication result could not be confirmed.',
                );
            }

            if (! $publish->succeeded()) {
                if ($publish->exitCode === 255) {
                    $this->restoreSnapshot($process, $connection, $target, $session['uid'], $paths, $snapshot);
                }

                $this->fail($process, 'publish', 'process.launchd_converge_failed', $publish);
            }

            try {
                if ($process->desired_state === DesiredProcessState::Running) {
                    $this->startUnlocked(
                        $process,
                        $connection,
                        $session['uid'],
                        $paths['label'],
                        $paths['plist'],
                        forceReload: true,
                    );
                }

                if ($process->desired_state !== DesiredProcessState::Running) {
                    $this->stopUnlockedWhileToleratingMissing(
                        $process,
                        $connection,
                        $session['uid'],
                        $paths['label'],
                    );
                }
            } catch (Throwable $exception) {
                $this->restoreSnapshot($process, $connection, $target, $session['uid'], $paths, $snapshot);

                if ($exception instanceof ProcessOperationException) {
                    throw $exception;
                }

                throw new ProcessOperationException(
                    step: 'activate-launchd-state',
                    errorCode: 'process.launchd_converge_failed',
                    message: 'The published launchd process definition could not be activated.',
                );
            }

            try {
                $cleanup = $this->cleanup($process, $connection, $target, $paths);
            } catch (Throwable) {
                throw new ProcessOperationException(
                    step: 'finalize-launchd-state',
                    errorCode: 'process.launchd_recovery_required',
                    message: 'The launchd recovery state could not be finalized.',
                );
            }

            if (! $cleanup->succeeded()) {
                $this->fail($process, 'finalize-launchd-state', 'process.launchd_recovery_required', $cleanup);
            }
        });
    }

    public function start(#[SensitiveParameter] Process $process): void
    {
        $this->withRuntimeLock($process, function (ProcessTarget $target, SshConnection $connection) use (
            $process,
        ): void {
            $session = $this->userSession($process, $connection);
            $paths = $this->paths($process, $target);
            $this->assertSafePaths($process, $connection, $target, $paths, prepareLogs: false);
            $this->assertPlistPresent($process, $connection, $paths['plist']);
            $this->startUnlocked(
                $process,
                $connection,
                $session['uid'],
                $paths['label'],
                $paths['plist'],
                forceReload: false,
            );
        });
    }

    public function stop(#[SensitiveParameter] Process $process): void
    {
        $this->withRuntimeLock($process, function (ProcessTarget $target, SshConnection $connection) use (
            $process,
        ): void {
            $session = $this->userSession($process, $connection);
            $paths = $this->paths($process, $target);
            $this->assertSafePaths($process, $connection, $target, $paths, prepareLogs: false);
            $this->assertPlistPresent($process, $connection, $paths['plist']);
            $this->stopUnlockedWhileToleratingMissing($process, $connection, $session['uid'], $paths['label']);
        });
    }

    public function restart(#[SensitiveParameter] Process $process): void
    {
        $this->withRuntimeLock($process, function (ProcessTarget $target, SshConnection $connection) use (
            $process,
        ): void {
            $session = $this->userSession($process, $connection);
            $paths = $this->paths($process, $target);
            $this->assertSafePaths($process, $connection, $target, $paths, prepareLogs: false);
            $this->assertPlistPresent($process, $connection, $paths['plist']);
            $this->stopUnlockedWhileToleratingMissing($process, $connection, $session['uid'], $paths['label']);
            $this->startUnlocked(
                $process,
                $connection,
                $session['uid'],
                $paths['label'],
                $paths['plist'],
                forceReload: true,
            );
        });
    }

    public function remove(#[SensitiveParameter] Process $process): void
    {
        $this->withRuntimeLock($process, function (ProcessTarget $target, SshConnection $connection) use (
            $process,
        ): void {
            $session = $this->userSession($process, $connection);
            $paths = $this->paths($process, $target);
            $this->assertSafePaths($process, $connection, $target, $paths, prepareLogs: false);
            $this->stopUnlockedWhileToleratingMissing($process, $connection, $session['uid'], $paths['label']);
            $remove = $this->execute($process, $connection, new RemoteCommand([
                '/bin/bash',
                '-seu',
                '-c',
                self::REMOVE_SCRIPT,
                'orbit-launchd-remove',
                $target->user,
                $paths['label'],
                $paths['plist'],
                $paths['stdout'],
                $paths['stderr'],
            ]));

            if (! $remove->succeeded()) {
                $this->fail($process, 'remove', 'process.remove_failed', $remove);
            }
        });
    }

    public function status(#[SensitiveParameter] Process $process): string
    {
        $target = $this->targets->forProcess($process);
        $connection = $this->connections->make($target->node);
        $session = $this->userSession($process, $connection);
        $paths = $this->paths($process, $target);
        $this->assertSafePaths($process, $connection, $target, $paths, prepareLogs: false);
        $status = $this->execute($process, $connection, new RemoteCommand([
            '/bin/launchctl',
            'print',
            "gui/{$session['uid']}/{$paths['label']}",
        ]));

        $service = "gui/{$session['uid']}/{$paths['label']}";

        if ($this->isLaunchdNotFound($status, $service)) {
            return 'absent';
        }

        if (! $status->succeeded()) {
            $this->fail($process, 'status', 'process.status_failed', $status);
        }

        if (preg_match('/^\s*state\s*=\s*running\s*$/mi', $status->stdout) === 1) {
            return 'running';
        }

        if (preg_match('/^\s*state\s*=\s*not running\s*$/mi', $status->stdout) === 1) {
            return 'stopped';
        }

        return 'unknown';
    }

    public function logs(#[SensitiveParameter] Process $process, int $lines): string
    {
        $target = $this->targets->forProcess($process);
        $connection = $this->connections->make($target->node);
        $paths = $this->paths($process, $target);
        $this->assertSafePaths($process, $connection, $target, $paths, prepareLogs: false);
        $clamped = max(1, min(1000, $lines));
        $logs = $this->execute($process, $connection, new RemoteCommand([
            '/usr/bin/tail',
            '-n',
            (string) $clamped,
            '--',
            $paths['stdout'],
            $paths['stderr'],
        ]));

        if (! $logs->succeeded()) {
            $this->fail($process, 'logs', 'process.logs_failed', $logs);
        }

        return $logs->stdout;
    }

    /** @return array{uid: string, gui: string} */
    private function userSession(#[SensitiveParameter] Process $process, SshConnection $connection): array
    {
        $identity = $this->execute($process, $connection, new RemoteCommand(['/usr/bin/id', '-u']));
        $uid = trim($identity->stdout);

        if (! $identity->succeeded() || preg_match('/\A[1-9][0-9]*\z/D', $uid) !== 1) {
            $this->fail($process, 'resolve-user', 'process.status_failed', $identity);
        }

        $session = $this->execute(
            $process,
            $connection,
            new RemoteCommand(['/bin/launchctl', 'print', "gui/{$uid}"]),
        );

        if (! $session->succeeded()) {
            throw new ResourceOperationException(
                errorCode: 'macos.user_session_unavailable',
                message: 'The macOS GUI user session is not available for runtime [launchd].',
                status: 409,
                safeDetails: ['runtime' => 'launchd'],
            );
        }

        return ['uid' => $uid, 'gui' => "gui/{$uid}"];
    }

    /** @return array{loaded: bool, running: bool, existed: bool} */
    private function snapshot(
        #[SensitiveParameter]
        Process $process,
        SshConnection $connection,
        string $uid,
        string $label,
        string $plist,
    ): array {
        $service = "gui/{$uid}/{$label}";
        $state = $this->execute($process, $connection, new RemoteCommand(['/bin/launchctl', 'print', $service]));

        if (! $state->succeeded() && ! $this->isLaunchdNotFound($state, $service)) {
            $this->fail($process, 'snapshot-runtime', 'process.launchd_snapshot_failed', $state);
        }

        return [
            'loaded' => $state->succeeded(),
            'running' => $state->succeeded() && preg_match('/^\s*state\s*=\s*running\s*$/mi', $state->stdout) === 1,
            'existed' => $this->plistExists($process, $connection, $plist),
        ];
    }

    /**
     * @param array{label: string, plist: string, stdout: string, stderr: string} $paths
     * @param array{loaded: bool, running: bool, existed: bool} $snapshot
     * @mago-expect lint:excessive-parameter-list Rollback needs the pinned connection, target identity, paths, and snapshot.
     */
    private function rollback(
        #[SensitiveParameter]
        Process $process,
        SshConnection $connection,
        ProcessTarget $target,
        string $uid,
        array $paths,
        array $snapshot,
    ): CommandResult {
        return $this->execute($process, $connection, new RemoteCommand([
            '/bin/bash',
            '-seu',
            '-c',
            self::ROLLBACK_SCRIPT,
            'orbit-launchd-rollback',
            $target->user,
            $paths['label'],
            "gui/{$uid}",
            $paths['plist'],
            $snapshot['existed'] ? '1' : '0',
            $snapshot['loaded'] ? '1' : '0',
            $snapshot['running'] ? '1' : '0',
        ]));
    }

    /**
     * @param array{label: string, plist: string, stdout: string, stderr: string} $paths
     * @param array{loaded: bool, running: bool, existed: bool} $snapshot
     * @mago-expect lint:excessive-parameter-list Snapshot restoration keeps the complete recovery boundary explicit.
     */
    private function restoreSnapshot(
        #[SensitiveParameter]
        Process $process,
        SshConnection $connection,
        ProcessTarget $target,
        string $uid,
        array $paths,
        array $snapshot,
    ): void {
        try {
            $rollback = $this->rollback($process, $connection, $target, $uid, $paths, $snapshot);
        } catch (Throwable) {
            throw new ProcessOperationException(
                step: 'restore-launchd-state',
                errorCode: 'process.launchd_recovery_required',
                message: 'The launchd rollback could not restore the previous state.',
            );
        }

        if (! $rollback->succeeded()) {
            throw new ProcessOperationException(
                step: 'restore-launchd-state',
                errorCode: 'process.launchd_recovery_required',
                message: 'The launchd rollback could not restore the previous state.',
                result: $this->redactedResult($process, $rollback),
            );
        }
    }

    /** @param array{label: string, plist: string, stdout: string, stderr: string} $paths */
    private function cleanup(
        #[SensitiveParameter]
        Process $process,
        SshConnection $connection,
        ProcessTarget $target,
        array $paths,
    ): CommandResult {
        return $this->execute($process, $connection, new RemoteCommand([
            '/bin/bash',
            '-seu',
            '-c',
            self::CLEANUP_SCRIPT,
            'orbit-launchd-cleanup',
            $target->user,
            $paths['label'],
            $paths['plist'],
        ]));
    }

    /**
     * @mago-expect lint:excessive-parameter-list Launchd activation needs the pinned connection and exact service identity.
     * @mago-expect lint:halstead The method preserves enable, reload, kickstart, and bounded readiness order.
     * @mago-expect lint:no-boolean-flag-parameter The flag distinguishes idempotent start from a required definition reload.
     */
    private function startUnlocked(
        #[SensitiveParameter]
        Process $process,
        SshConnection $connection,
        string $uid,
        string $label,
        string $plist,
        bool $forceReload,
    ): void {
        $service = "gui/{$uid}/{$label}";
        $this->executeSuccessfully(
            $process,
            $connection,
            ['/bin/launchctl', 'enable', $service],
            'start',
            'process.start_failed',
        );

        if (! $forceReload) {
            $current = $this->execute(
                $process,
                $connection,
                new RemoteCommand(['/bin/launchctl', 'print', $service]),
            );

            if ($current->succeeded() && preg_match('/^\s*state\s*=\s*running\s*$/mi', $current->stdout) === 1) {
                return;
            }

            if (
                $current->succeeded()
                && preg_match('/^\s*state\s*=\s*not running\s*$/mi', $current->stdout) !== 1
                || ! $current->succeeded()
                && ! $this->isLaunchdNotFound($current, $service)
            ) {
                $this->fail($process, 'start-probe', 'process.start_failed', $current);
            }
        }

        $bootout = $this->execute(
            $process,
            $connection,
            new RemoteCommand(['/bin/launchctl', 'bootout', $service]),
        );

        if (! $bootout->succeeded() && ! $this->isLaunchdNotFound($bootout, $service)) {
            $this->fail($process, 'start-bootout', 'process.start_failed', $bootout);
        }

        $this->executeSuccessfully(
            $process,
            $connection,
            ['/bin/launchctl', 'bootstrap', "gui/{$uid}", $plist],
            'start-bootstrap',
            'process.start_failed',
        );
        $this->executeSuccessfully(
            $process,
            $connection,
            ['/bin/launchctl', 'kickstart', '-k', $service],
            'start',
            'process.start_failed',
        );

        $deadline = microtime(true) + max(0.1, $this->startReadinessTimeoutSeconds);
        $attempt = 0;

        while (true) {
            $status = $this->execute(
                $process,
                $connection,
                new RemoteCommand(['/bin/launchctl', 'print', $service]),
            );

            if ($status->succeeded() && preg_match('/^\s*state\s*=\s*running\s*$/mi', $status->stdout) === 1) {
                return;
            }

            if (! $status->succeeded() && ! $this->isLaunchdNotFound($status, $service)) {
                $this->fail($process, 'start-readiness', 'process.start_failed', $status);
            }

            $attempt++;

            if (
                $this->startReadinessAttempts !== null
                && $attempt >= max(1, $this->startReadinessAttempts)
                || microtime(true) >= $deadline
            ) {
                break;
            }

            usleep(max(0, $this->startReadinessPollMicroseconds));
        }

        throw new ProcessOperationException(
            step: 'start-readiness',
            errorCode: 'process.start_failed',
            message: 'The launchd service did not become ready.',
        );
    }

    private function stopUnlockedWhileToleratingMissing(
        #[SensitiveParameter]
        Process $process,
        SshConnection $connection,
        string $uid,
        string $label,
    ): void {
        $this->stopLaunchd($process, $connection, $uid, $label);
    }

    private function stopLaunchd(
        #[SensitiveParameter]
        Process $process,
        SshConnection $connection,
        string $uid,
        string $label,
    ): void {
        $service = "gui/{$uid}/{$label}";
        $disable = $this->execute(
            $process,
            $connection,
            new RemoteCommand(['/bin/launchctl', 'disable', $service]),
        );

        if (! $disable->succeeded() && ! $this->isLaunchdNotFound($disable, $service)) {
            $this->fail($process, 'stop-disable', 'process.stop_failed', $disable);
        }

        $bootout = $this->execute(
            $process,
            $connection,
            new RemoteCommand(['/bin/launchctl', 'bootout', $service]),
        );

        if (! $bootout->succeeded() && ! $this->isLaunchdNotFound($bootout, $service)) {
            $this->fail($process, 'stop-bootout', 'process.stop_failed', $bootout);
        }
    }

    /** @param callable(ProcessTarget, SshConnection): void $callback */
    private function withRuntimeLock(#[SensitiveParameter] Process $process, callable $callback): void
    {
        $target = $this->targets->forProcess($process);
        $lock = Cache::lock("orbit:process-runtime:{$target->node->id}:{$process->id}", 3_600);

        if (! $lock->get()) {
            throw new ProcessOperationException(
                step: 'lock-runtime',
                errorCode: 'process.runtime_lock_failed',
                message: 'The process runtime is busy.',
            );
        }

        try {
            $connection = $this->connections->make($target->node);
            $callback($target, $connection);
        } finally {
            $lock->release();
        }
    }

    /**
     * @param array{label: string, plist: string, stdout: string, stderr: string} $paths
     * @mago-expect lint:no-boolean-flag-parameter The flag selects read-only checks or bounded log-directory preparation.
     */
    private function assertSafePaths(
        #[SensitiveParameter]
        Process $process,
        SshConnection $connection,
        ProcessTarget $target,
        array $paths,
        bool $prepareLogs,
    ): void {
        $home = "/Users/{$target->user}";
        $result = $this->execute($process, $connection, new RemoteCommand(
            arguments: [
                '/bin/bash',
                '-seu',
                '--',
                $target->user,
                $paths['label'],
                $prepareLogs ? '1' : '0',
                $home,
                "{$home}/.orbit",
                "{$home}/Library",
                "{$home}/Library/LaunchAgents",
                "{$home}/Library/Logs",
                "{$home}/Library/Logs/Orbit",
                "{$home}/Library/Logs/Orbit/processes",
                $paths['plist'],
                $paths['stdout'],
                $paths['stderr'],
            ],
            input: self::PATH_CHECK_SCRIPT,
        ));

        if (! $result->succeeded()) {
            $this->fail($process, 'inspect-paths', 'process.launchd_path_unsafe', $result);
        }
    }

    private function assertPlistPresent(
        #[SensitiveParameter]
        Process $process,
        SshConnection $connection,
        string $plist,
    ): void {
        if ($this->plistExists($process, $connection, $plist)) {
            return;
        }

        throw new ProcessOperationException(
            step: 'inspect-runtime',
            errorCode: 'process.runtime_not_found',
            message: 'The launchd process definition does not exist.',
        );
    }

    private function plistExists(
        #[SensitiveParameter]
        Process $process,
        SshConnection $connection,
        string $plist,
    ): bool {
        $result = $this->execute($process, $connection, new RemoteCommand(['/bin/test', '-e', $plist]));

        if ($result->succeeded()) {
            return true;
        }

        if ($result->exitCode === 1 && $result->stdout === '' && $result->stderr === '') {
            return false;
        }

        $this->fail($process, 'inspect-plist', 'process.launchd_snapshot_failed', $result);
    }

    private function execute(
        #[SensitiveParameter]
        Process $process,
        SshConnection $connection,
        #[SensitiveParameter]
        RemoteCommand $command,
    ): CommandResult {
        return $this->ssh->execute($connection, $this->guard->guard($command));
    }

    /** @param non-empty-list<string> $arguments */
    private function executeSuccessfully(
        #[SensitiveParameter]
        Process $process,
        SshConnection $connection,
        array $arguments,
        string $step,
        string $errorCode,
    ): CommandResult {
        $result = $this->execute($process, $connection, new RemoteCommand($arguments));

        if (! $result->succeeded()) {
            $this->fail($process, $step, $errorCode, $result);
        }

        return $result;
    }

    private function fail(
        #[SensitiveParameter]
        Process $process,
        string $step,
        string $errorCode,
        #[SensitiveParameter]
        CommandResult $result,
    ): never {
        throw new ProcessOperationException(
            step: $step,
            errorCode: $errorCode,
            message: 'The process runtime operation failed.',
            result: $this->redactedResult($process, $result),
        );
    }

    /** @mago-expect analysis:mixed-assignment Persisted JSON values start at an untyped boundary. */
    private function redactedResult(
        #[SensitiveParameter]
        Process $process,
        #[SensitiveParameter]
        CommandResult $result,
    ): CommandResult {
        $environment = $process->runtime_config['environment'] ?? null;
        $values = [];

        if (is_array($environment)) {
            foreach ($environment as $value) {
                if (! is_string($value) || $value === '') {
                    continue;
                }

                $values[] = $value;
            }
        }

        $values = array_values(array_unique($values));
        usort($values, static fn (string $first, string $second): int => strlen($second) <=> strlen($first));
        $stdout = str_replace(search: $values, replace: '[REDACTED]', subject: $result->stdout);
        $stderr = str_replace(search: $values, replace: '[REDACTED]', subject: $result->stderr);

        return new CommandResult(
            $result->exitCode,
            $this->sanitizer->sanitizeDiagnostics($stdout),
            $this->sanitizer->sanitizeDiagnostics($stderr),
            $result->durationMs,
            $result->truncated,
        );
    }

    private function isLaunchdNotFound(#[SensitiveParameter] CommandResult $result, string $service): bool
    {
        if ($result->succeeded()) {
            return false;
        }

        $output = trim("{$result->stdout}\n{$result->stderr}");
        $segments = explode('/', $service, limit: 3);
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
                ['Could not find service', 'service could not be found', 'No such process'],
                strict: true,
            )
            || $canonical !== null
            && $output === $canonical
            || $canonical !== null
            && $output === "Bad request.\n{$canonical}"
            || $output === 'Boot-out failed: 3: No such process'
        );
    }

    /** @return array{label: string, plist: string, stdout: string, stderr: string} */
    private function paths(#[SensitiveParameter] Process $process, ProcessTarget $target): array
    {
        return [
            'label' => $this->renderer->label($process),
            'plist' => $this->renderer->plistPath($process, $target),
            'stdout' => $this->renderer->stdoutPath($process, $target),
            'stderr' => $this->renderer->stderrPath($process, $target),
        ];
    }
}
