<?php

declare(strict_types=1);

namespace App\Infrastructure\Processes;

use App\Domain\Processes\DesiredProcessState;
use App\Domain\Processes\ProcessOperationException;
use App\Domain\Processes\ProcessRuntime;
use App\Domain\Processes\ProcessRuntimeManager;
use App\Domain\Processes\ProcessTarget;
use App\Domain\Processes\ProcessTargetResolver;
use App\Infrastructure\Ssh\KnownHostsStore;
use App\Infrastructure\Ssh\RemoteCommand;
use App\Infrastructure\Ssh\SshConnection;
use App\Infrastructure\Ssh\SshExecutor;
use App\Infrastructure\Ssh\SshKeyProvider;
use App\Models\Process;
use Closure;
use Illuminate\Support\Facades\Cache;
use SensitiveParameter;

/**
 * @mago-expect lint:cyclomatic-complexity Runtime convergence keeps its ordered recovery gates together.
 * @mago-expect lint:kan-defect Runtime convergence fails closed at each remote state transition.
 * @mago-expect lint:too-many-methods Public lifecycle methods and private recovery steps form one runtime boundary.
 * @mago-expect lint:excessive-parameter-list The runtime needs the SSH boundary, target resolver, and two renderers.
 */
final readonly class RemoteProcessRuntimeManager implements ProcessRuntimeManager
{
    private const string DOCKER_INSPECT_FORMAT = '{{ index .Config.Labels "orbit.managed" }}{{ printf "\\n" }}{{ index .Config.Labels "orbit.container.kind" }}{{ printf "\\n" }}{{ index .Config.Labels "orbit.process.id" }}{{ printf "\\n" }}{{ index .Config.Labels "orbit.process.spec" }}{{ printf "\\n" }}{{ .State.Running }}';

    private const string DOCKER_OWNER_FORMAT = '{{ index .Config.Labels "orbit.managed" }}{{ printf "\\n" }}{{ index .Config.Labels "orbit.container.kind" }}{{ printf "\\n" }}{{ index .Config.Labels "orbit.process.id" }}';

    private const string DOCKER_CREATE_SCRIPT = <<<'BASH'
        umask 077
        environment_file=$(mktemp /tmp/orbit-process-environment.XXXXXX)
        trap 'rm -f -- "$environment_file"' EXIT
        cat > "$environment_file"
        chmod 0600 "$environment_file"
        sudo docker container create --env-file "$environment_file" "$@"
        BASH;

    private const string SYSTEMD_CANDIDATE_DIRECTORY = '/etc/orbit/systemd-candidates';

    public function __construct(
        private ProcessTargetResolver $targets,
        private SshExecutor $ssh,
        private SshKeyProvider $keys,
        private KnownHostsStore $knownHosts,
        private SystemdProcessRenderer $systemd,
        private DockerProcessRenderer $docker,
    ) {}

    public function converge(#[SensitiveParameter] Process $process): void
    {
        $this->withRuntimeLock($process, function () use ($process): void {
            $target = $this->targets->forProcess($process);

            match ($process->runtime) {
                ProcessRuntime::Systemd => $this->convergeAndActivateSystemd($process, $target),
                ProcessRuntime::Docker => $this->convergeDocker($process, $target),
            };
        });
    }

    public function start(#[SensitiveParameter] Process $process): void
    {
        $this->withRuntimeLock($process, function () use ($process): void {
            $this->startUnlocked($process);
        });
    }

    public function stop(#[SensitiveParameter] Process $process): void
    {
        $this->withRuntimeLock($process, function () use ($process): void {
            $this->stopUnlocked($process);
        });
    }

    public function restart(#[SensitiveParameter] Process $process): void
    {
        $this->withRuntimeLock($process, function () use ($process): void {
            $this->restartUnlocked($process);
        });
    }

    public function remove(#[SensitiveParameter] Process $process): void
    {
        $target = $this->targets->forRemoval($process);
        $this->withRuntimeLock(
            $process,
            function () use ($process, $target): void {
                $this->removeUnlocked($process, $target);
            },
            $target,
        );
    }

    private function startUnlocked(#[SensitiveParameter] Process $process): void
    {
        $this->requireOwnedRuntime($process, 'start', 'process.start_failed');

        $arguments = match ($process->runtime) {
            ProcessRuntime::Systemd => [
                'sudo',
                'systemctl',
                'enable',
                '--now',
                $this->systemd->unitName($process),
            ],
            ProcessRuntime::Docker => [
                'sudo',
                'docker',
                'container',
                'start',
                $this->docker->containerName($process),
            ],
        };

        $this->executeSuccessfully($process, $arguments, 'start', 'process.start_failed');
    }

    private function stopUnlocked(#[SensitiveParameter] Process $process): void
    {
        $this->requireOwnedRuntime($process, 'stop', 'process.stop_failed');

        $arguments = match ($process->runtime) {
            ProcessRuntime::Systemd => [
                'sudo',
                'systemctl',
                'disable',
                '--now',
                $this->systemd->unitName($process),
            ],
            ProcessRuntime::Docker => [
                'sudo',
                'docker',
                'container',
                'stop',
                $this->docker->containerName($process),
            ],
        };

        $this->executeSuccessfully($process, $arguments, 'stop', 'process.stop_failed');
    }

    private function restartUnlocked(#[SensitiveParameter] Process $process): void
    {
        $this->requireOwnedRuntime($process, 'restart', 'process.restart_failed');

        if ($process->runtime === ProcessRuntime::Docker) {
            $this->executeSuccessfully(
                $process,
                ['sudo', 'docker', 'container', 'restart', $this->docker->containerName($process)],
                'restart',
                'process.restart_failed',
            );

            return;
        }

        $this->executeSuccessfully(
            $process,
            ['sudo', 'systemctl', 'enable', $this->systemd->unitName($process)],
            'restart-enable',
            'process.restart_failed',
        );
        $this->executeSuccessfully(
            $process,
            ['sudo', 'systemctl', 'restart', $this->systemd->unitName($process)],
            'restart',
            'process.restart_failed',
        );
    }

    private function removeUnlocked(#[SensitiveParameter] Process $process, ProcessTarget $target): void
    {
        if ($process->runtime === ProcessRuntime::Docker) {
            $this->removeDockerArtifacts($process, $target);

            return;
        }

        if (! $this->runtimeExistsAndIsOwned($process, 'inspect-runtime', 'process.remove_failed', $target)) {
            return;
        }

        $this->executeSuccessfully(
            $process,
            ['sudo', 'systemctl', 'disable', '--now', $this->systemd->unitName($process)],
            'stop',
            'process.remove_failed',
            target: $target,
        );
        $this->executeSuccessfully(
            $process,
            ['sudo', 'rm', '-f', '--', $this->systemd->unitPath($process)],
            'remove-unit',
            'process.remove_failed',
            target: $target,
        );
        $this->executeSuccessfully(
            $process,
            ['sudo', 'systemctl', 'daemon-reload'],
            'daemon-reload',
            'process.remove_failed',
            target: $target,
        );
    }

    private function removeDockerArtifacts(#[SensitiveParameter] Process $process, ProcessTarget $target): void
    {
        $name = $this->docker->containerName($process);
        $artifacts = [
            $name => $this->inspectOwnedDockerContainer($process, $name, 'inspect-runtime', $target),
            "{$name}-rollback-running" => $this->inspectOwnedDockerContainer(
                $process,
                "{$name}-rollback-running",
                'inspect-runtime',
                $target,
            ),
            "{$name}-rollback-stopped" => $this->inspectOwnedDockerContainer(
                $process,
                "{$name}-rollback-stopped",
                'inspect-runtime',
                $target,
            ),
            "{$name}-candidate" => $this->inspectOwnedDockerContainer(
                $process,
                "{$name}-candidate",
                'inspect-runtime',
                $target,
            ),
        ];

        foreach (["{$name}-candidate", $name, "{$name}-rollback-running", "{$name}-rollback-stopped"] as $artifact) {
            if ($artifacts[$artifact] === null) {
                continue;
            }

            $this->executeSuccessfully(
                $process,
                ['sudo', 'docker', 'container', 'rm', '--force', $artifact],
                'remove',
                'process.remove_failed',
                target: $target,
            );
        }
    }

    public function status(#[SensitiveParameter] Process $process): string
    {
        if (! $this->runtimeExistsAndIsOwned($process, 'status', 'process.status_failed')) {
            return 'absent';
        }

        $arguments = match ($process->runtime) {
            ProcessRuntime::Systemd => [
                'sudo',
                'systemctl',
                'is-active',
                $this->systemd->unitName($process),
            ],
            ProcessRuntime::Docker => [
                'sudo',
                'docker',
                'container',
                'inspect',
                '--format',
                '{{.State.Status}}',
                $this->docker->containerName($process),
            ],
        };
        $result = $this->execute($process, $arguments);
        $status = trim($result->stdout);

        if ($this->isNativeNotFound($process->runtime, $result)) {
            return 'absent';
        }

        if ($result->succeeded()) {
            return $status !== '' ? $status : 'unknown';
        }

        if (
            $process->runtime === ProcessRuntime::Systemd
            && in_array(
                $status,
                ['active', 'reloading', 'inactive', 'failed', 'activating', 'deactivating', 'maintenance'],
                strict: true,
            )
        ) {
            return $status;
        }

        $this->fail($process, 'status', 'process.status_failed', $result);
    }

    public function logs(#[SensitiveParameter] Process $process, int $lines): string
    {
        $this->requireOwnedRuntime($process, 'logs', 'process.logs_failed');

        $arguments = match ($process->runtime) {
            ProcessRuntime::Systemd => [
                'sudo',
                'journalctl',
                '--unit',
                $this->systemd->unitName($process),
                '--lines',
                (string) $lines,
                '--no-pager',
                '--output',
                'short-iso',
            ],
            ProcessRuntime::Docker => [
                'sudo',
                'docker',
                'container',
                'logs',
                '--tail',
                (string) $lines,
                $this->docker->containerName($process),
            ],
        };

        return $this->executeSuccessfully(
            $process,
            $arguments,
            'logs',
            'process.logs_failed',
        )->stdout;
    }

    public function dockerSpecHash(#[SensitiveParameter] Process $process): string
    {
        return $this->docker->specHash($process, $this->targets->forProcess($process));
    }

    private function withRuntimeLock(
        #[SensitiveParameter]
        Process $process,
        Closure $operation,
        ?ProcessTarget $target = null,
    ): void {
        $target ??= $this->targets->forProcess($process);
        $lock = Cache::lock("orbit:process-runtime:{$target->node->id}:{$process->id}", 3_600);

        if (! $lock->get()) {
            throw new ProcessOperationException(
                step: 'lock-runtime',
                errorCode: 'process.runtime_lock_failed',
                message: "Process [{$process->name}] runtime mutation is already active.",
            );
        }

        try {
            $operation();
        } finally {
            $lock->release();
        }
    }

    private function convergeAndActivateSystemd(
        #[SensitiveParameter]
        Process $process,
        ProcessTarget $target,
    ): void {
        $hadPreviousUnit = $this->convergeSystemd($process, $target);
        $activation = $this->activateSystemdDesiredState($process);

        if (! $activation->succeeded()) {
            if ($hadPreviousUnit) {
                $this->rollbackSystemdReplacement($process);
            }

            if (! $hadPreviousUnit) {
                $this->removeFailedNewSystemdUnit($process);
            }

            $state = $process->desired_state === DesiredProcessState::Running ? 'start' : 'stop';
            $restoration = $hadPreviousUnit ? 'the previous unit was restored' : 'the new unit was removed';

            throw new ProcessOperationException(
                step: $state,
                errorCode: "process.{$state}_failed",
                message: "Process [{$process->name}] failed to {$state}; {$restoration}.",
                result: $activation,
            );
        }

        if ($hadPreviousUnit) {
            $this->executeSuccessfully(
                $process,
                ['sudo', 'rm', '-f', '--', $this->systemdBackupPath($process)],
                'remove-unit-backup',
                'process.systemd_converge_failed',
            );
        }
    }

    private function convergeSystemd(#[SensitiveParameter] Process $process, ProcessTarget $target): bool
    {
        $path = $this->systemd->unitPath($process);
        $candidate = $this->systemdCandidatePath($process);
        $backup = $this->systemdBackupPath($process);
        $exists = $this->execute($process, ['sudo', 'test', '-e', $path]);
        $hadPreviousUnit = $exists->succeeded();

        if (! $hadPreviousUnit && ! $this->isSystemdPathAbsent($exists)) {
            $this->fail($process, 'inspect-unit', 'process.systemd_converge_failed', $exists);
        }

        if ($hadPreviousUnit) {
            $this->assertSystemdUnitOwnedForConvergence($process, $path);
        }

        $this->executeSuccessfully(
            $process,
            ['sudo', 'install', '-d', '-m', '0755', self::SYSTEMD_CANDIDATE_DIRECTORY],
            'prepare-unit-candidate',
            'process.systemd_converge_failed',
        );
        $this->executeSuccessfully(
            $process,
            ['sudo', 'install', '-m', '0644', '/dev/stdin', $candidate],
            'stage-unit',
            'process.systemd_converge_failed',
            $this->systemd->render($process, $target),
        );
        $validation = $this->execute(
            $process,
            ['sudo', 'systemd-analyze', 'verify', $candidate],
        );

        if (! $validation->succeeded()) {
            $this->execute($process, ['sudo', 'rm', '-f', '--', $candidate]);

            throw new ProcessOperationException(
                step: 'verify-unit',
                errorCode: 'process.systemd_candidate_invalid',
                message: "Process [{$process->name}] systemd candidate validation failed.",
                result: $validation,
            );
        }

        if ($hadPreviousUnit) {
            $this->executeSuccessfully(
                $process,
                ['sudo', 'cp', '--preserve=mode,ownership,timestamps', '--', $path, $backup],
                'backup-unit',
                'process.systemd_converge_failed',
            );
        }

        $this->executeSuccessfully(
            $process,
            ['sudo', 'mv', '--', $candidate, $path],
            'activate-unit',
            'process.systemd_converge_failed',
        );
        $activation = $this->execute($process, ['sudo', 'systemctl', 'daemon-reload']);

        if (! $activation->succeeded()) {
            $restoreArguments = $hadPreviousUnit
                ? ['sudo', 'mv', '--', $backup, $path]
                : ['sudo', 'rm', '-f', '--', $path];
            $this->restoreSystemdUnit($process, $restoreArguments);

            throw new ProcessOperationException(
                step: 'daemon-reload',
                errorCode: 'process.systemd_activation_failed',
                message: "Process [{$process->name}] systemd activation failed; the previous unit was restored.",
                result: $activation,
            );
        }

        return $hadPreviousUnit;
    }

    private function activateSystemdDesiredState(#[SensitiveParameter] Process $process): CommandResult
    {
        $unit = $this->systemd->unitName($process);

        if ($process->desired_state === DesiredProcessState::Stopped) {
            return $this->execute($process, ['sudo', 'systemctl', 'disable', '--now', $unit]);
        }

        $enable = $this->execute($process, ['sudo', 'systemctl', 'enable', $unit]);

        if (! $enable->succeeded()) {
            return $enable;
        }

        return $this->execute($process, ['sudo', 'systemctl', 'restart', $unit]);
    }

    private function rollbackSystemdReplacement(#[SensitiveParameter] Process $process): void
    {
        $unit = $this->systemd->unitName($process);
        $path = $this->systemd->unitPath($process);
        $this->quiesceFailedSystemdReplacement($process, $unit);
        $this->restoreSystemdUnit(
            $process,
            ['sudo', 'mv', '--', $this->systemdBackupPath($process), $path],
        );

        $restoreState = $process->desired_state === DesiredProcessState::Running
            ? ['sudo', 'systemctl', 'enable', '--now', $unit]
            : ['sudo', 'systemctl', 'disable', '--now', $unit];
        $this->executeSuccessfully(
            $process,
            $restoreState,
            'restore-service-state',
            'process.systemd_rollback_failed',
        );
    }

    private function removeFailedNewSystemdUnit(#[SensitiveParameter] Process $process): void
    {
        $unit = $this->systemd->unitName($process);
        $this->quiesceFailedSystemdReplacement($process, $unit);
        $this->restoreSystemdUnit(
            $process,
            ['sudo', 'rm', '-f', '--', $this->systemd->unitPath($process)],
        );
    }

    private function quiesceFailedSystemdReplacement(
        #[SensitiveParameter]
        Process $process,
        string $unit,
    ): void {
        $quiesce = $this->execute($process, ['sudo', 'systemctl', 'disable', '--now', $unit]);

        if (! $quiesce->succeeded()) {
            $this->fail($process, 'stop-replacement-unit', 'process.systemd_recovery_required', $quiesce);
        }
    }

    private function assertSystemdUnitOwnedForConvergence(
        #[SensitiveParameter]
        Process $process,
        string $path,
    ): void {
        $current = $this->executeSuccessfully(
            $process,
            ['sudo', 'cat', '--', $path],
            'inspect-unit',
            'process.systemd_converge_failed',
        );
        $ownershipMarker = preg_quote("X-Orbit-Process-ID={$process->id}", delimiter: '/');

        if (preg_match("/^{$ownershipMarker}\\r?$/mD", $current->stdout) === 1) {
            return;
        }

        throw new ProcessOperationException(
            step: 'inspect-unit',
            errorCode: 'process.runtime_name_collision',
            message: "Systemd unit [{$path}] is not owned by this process.",
            result: $current,
        );
    }

    private function convergeDocker(#[SensitiveParameter] Process $process, ProcessTarget $target): void
    {
        $name = $this->docker->containerName($process);
        $candidate = "{$name}-candidate";
        $desiredSpec = $this->docker->specHash($process, $target);
        $state = $this->recoverDockerArtifacts($process, $name, $candidate, $desiredSpec);

        if ($state['complete']) {
            if ($state['canonical'] === null) {
                throw new ProcessOperationException(
                    step: 'inspect-container',
                    errorCode: 'process.docker_recovery_required',
                    message: "Docker process [{$process->name}] has no canonical runtime after recovery.",
                );
            }

            $this->convergeDockerDesiredState($process, $name, $state['canonical']);

            return;
        }

        $canonicalState = $state['canonical'];
        $candidateState = $state['candidate'];
        $createName = $canonicalState === null ? $name : $candidate;
        $createArguments = $this->docker->createArguments($process, $target, $createName);
        $environmentInput = $this->docker->environmentInput($process);

        try {
            $this->removeOwnedDockerCandidate($process, $candidate, $candidateState);
            $this->createDockerContainer($process, $createArguments, $environmentInput);

            if ($canonicalState === null) {
                $createdCanonical = $this->inspectOwnedDockerContainer(
                    $process,
                    $name,
                    'verify-container',
                );

                if ($createdCanonical === null || $createdCanonical['spec'] !== $desiredSpec) {
                    throw new ProcessOperationException(
                        step: 'verify-container',
                        errorCode: 'process.docker_candidate_invalid',
                        message: "Docker container [{$name}] does not match the desired process specification.",
                        result: $createdCanonical['result'] ?? null,
                    );
                }

                $this->convergeDockerDesiredState($process, $name, $createdCanonical);

                return;
            }

            $createdCandidate = $this->inspectOwnedDockerContainer(
                $process,
                $candidate,
                'verify-candidate-container',
            );

            if ($createdCandidate === null || $createdCandidate['spec'] !== $desiredSpec) {
                $this->removeOwnedDockerCandidate($process, $candidate, $createdCandidate);

                throw new ProcessOperationException(
                    step: 'verify-candidate-container',
                    errorCode: 'process.docker_candidate_invalid',
                    message: "Docker candidate [{$candidate}] does not match the desired process specification.",
                    result: $createdCandidate['result'] ?? null,
                );
            }

            $this->publishDockerCandidate($process, $name, $candidate, $canonicalState);
        } finally {
            $environmentInput->close();
        }
    }

    /**
     * @return array{
     *     complete: bool,
     *     canonical: array{spec: string, running: bool, result: CommandResult}|null,
     *     candidate: array{spec: string, running: bool, result: CommandResult}|null
     * }
     */
    private function recoverDockerArtifacts(
        #[SensitiveParameter]
        Process $process,
        string $name,
        string $candidate,
        string $desiredSpec,
    ): array {
        $canonicalState = $this->inspectOwnedDockerContainer($process, $name, 'inspect-container');
        $runningRollback = "{$name}-rollback-running";
        $stoppedRollback = "{$name}-rollback-stopped";
        $runningRollbackState = $this->inspectOwnedDockerContainer(
            $process,
            $runningRollback,
            'inspect-rollback-container',
        );
        $stoppedRollbackState = $this->inspectOwnedDockerContainer(
            $process,
            $stoppedRollback,
            'inspect-rollback-container',
        );
        $candidateState = $this->inspectOwnedDockerContainer($process, $candidate, 'inspect-candidate-container');

        if ($runningRollbackState !== null && $stoppedRollbackState !== null) {
            throw new ProcessOperationException(
                step: 'inspect-rollback-container',
                errorCode: 'process.docker_recovery_required',
                message: "Docker process [{$process->name}] has ambiguous rollback state.",
                result: $runningRollbackState['result'],
            );
        }

        $rollback = $runningRollbackState !== null ? $runningRollback : $stoppedRollback;
        $rollbackState = $runningRollbackState ?? $stoppedRollbackState;

        if ($rollbackState !== null) {
            $canonicalState = $this->recoverDockerRollback(
                $process,
                $name,
                $candidate,
                $rollback,
                $desiredSpec,
                $canonicalState,
                $candidateState,
                $rollbackState,
            );

            $candidateState = $this->inspectOwnedDockerContainer(
                $process,
                $candidate,
                'inspect-candidate-container',
            );
        }

        if ($canonicalState !== null && $canonicalState['spec'] === $desiredSpec) {
            $this->removeOwnedDockerCandidate($process, $candidate, $candidateState);

            return ['complete' => true, 'canonical' => $canonicalState, 'candidate' => null];
        }

        if ($canonicalState === null && $candidateState !== null && $candidateState['spec'] === $desiredSpec) {
            $this->executeSuccessfully(
                $process,
                ['sudo', 'docker', 'container', 'rename', $candidate, $name],
                'recover-candidate-container',
                'process.docker_converge_failed',
            );

            return ['complete' => true, 'canonical' => $candidateState, 'candidate' => null];
        }

        return ['complete' => false, 'canonical' => $canonicalState, 'candidate' => $candidateState];
    }

    /**
     * @param non-empty-list<string> $createArguments
     */
    private function createDockerContainer(
        #[SensitiveParameter]
        Process $process,
        array $createArguments,
        #[SensitiveParameter]
        ProtectedInput $environmentInput,
    ): void {
        $this->executeSuccessfully(
            $process,
            [
                'bash',
                '-seu',
                '-c',
                self::DOCKER_CREATE_SCRIPT,
                'orbit-process-docker-create',
                ...array_slice($createArguments, offset: 4),
            ],
            'create-container',
            'process.docker_converge_failed',
            protectedInput: $environmentInput,
        );
    }

    /**
     * @param array{spec: string, running: bool, result: CommandResult}|null $canonicalState
     * @param array{spec: string, running: bool, result: CommandResult}|null $candidateState
     * @param array{spec: string, running: bool, result: CommandResult} $rollbackState
     * @return array{spec: string, running: bool, result: CommandResult}|null
     */
    private function recoverDockerRollback(
        #[SensitiveParameter]
        Process $process,
        string $name,
        string $candidate,
        string $rollback,
        string $desiredSpec,
        ?array $canonicalState,
        ?array $candidateState,
        array $rollbackState,
    ): ?array {
        if ($canonicalState === null) {
            if ($candidateState !== null && $candidateState['running']) {
                $stopCandidate = $this->execute(
                    $process,
                    ['sudo', 'docker', 'container', 'stop', $candidate],
                );

                if (! $stopCandidate->succeeded()) {
                    $this->fail(
                        $process,
                        'stop-recovery-candidate',
                        'process.docker_recovery_required',
                        $stopCandidate,
                    );
                }
            }

            $this->restoreDockerRollbackRuntime($process, $name, $rollback);

            return [
                ...$rollbackState,
                'running' => $this->dockerRollbackShouldRun($rollback),
            ];
        }

        if ($canonicalState['spec'] === $desiredSpec) {
            if ($candidateState !== null) {
                throw new ProcessOperationException(
                    step: 'inspect-rollback-container',
                    errorCode: 'process.docker_recovery_required',
                    message: "Docker process [{$process->name}] has ambiguous candidate and rollback state.",
                    result: $candidateState['result'],
                );
            }

            if (
                $process->desired_state === DesiredProcessState::Running
                && ! $canonicalState['running']
            ) {
                $this->rollbackPublishedDockerCandidate(
                    $process,
                    $name,
                    $candidate,
                    $rollback,
                );

                return [
                    ...$rollbackState,
                    'running' => $this->dockerRollbackShouldRun($rollback),
                ];
            }

            if (
                $process->desired_state === DesiredProcessState::Stopped
                && $canonicalState['running']
            ) {
                $this->executeSuccessfully(
                    $process,
                    ['sudo', 'docker', 'container', 'stop', $name],
                    'stop',
                    'process.stop_failed',
                );
            }

            $this->executeSuccessfully(
                $process,
                ['sudo', 'docker', 'container', 'rm', '--force', $rollback],
                'finalize-rollback-container',
                'process.docker_converge_failed',
            );

            return [
                ...$canonicalState,
                'running' => $process->desired_state === DesiredProcessState::Running,
            ];
        }

        throw new ProcessOperationException(
            step: 'inspect-rollback-container',
            errorCode: 'process.docker_recovery_required',
            message: "Docker process [{$process->name}] has ambiguous rollback state.",
            result: $rollbackState['result'],
        );
    }

    /** @param array{spec: string, running: bool, result: CommandResult}|null $candidateState */
    private function removeOwnedDockerCandidate(
        #[SensitiveParameter]
        Process $process,
        string $candidate,
        ?array $candidateState,
    ): void {
        if ($candidateState === null) {
            return;
        }

        $this->executeSuccessfully(
            $process,
            ['sudo', 'docker', 'container', 'rm', '--force', $candidate],
            'remove-candidate-container',
            'process.docker_converge_failed',
        );
    }

    /** @param array{spec: string, running: bool, result: CommandResult} $state */
    private function convergeDockerDesiredState(
        #[SensitiveParameter]
        Process $process,
        string $name,
        array $state,
    ): void {
        if ($process->desired_state === DesiredProcessState::Running) {
            if ($state['running']) {
                return;
            }

            $this->executeSuccessfully(
                $process,
                ['sudo', 'docker', 'container', 'start', $name],
                'start',
                'process.start_failed',
            );

            return;
        }

        if (! $state['running']) {
            return;
        }

        $this->executeSuccessfully(
            $process,
            ['sudo', 'docker', 'container', 'stop', $name],
            'stop',
            'process.stop_failed',
        );
    }

    /** @param array{spec: string, running: bool, result: CommandResult} $previousState */
    private function publishDockerCandidate(
        #[SensitiveParameter]
        Process $process,
        string $name,
        string $candidate,
        array $previousState,
    ): void {
        $rollback = $previousState['running']
            ? "{$name}-rollback-running"
            : "{$name}-rollback-stopped";
        $stageRollback = $this->execute(
            $process,
            ['sudo', 'docker', 'container', 'rename', $name, $rollback],
        );

        if (! $stageRollback->succeeded()) {
            $this->removeDockerCandidateAfterFailedActivation($process, $candidate);
            $this->throwDockerActivationFailure($process, 'stage-rollback-container', $stageRollback);
        }

        if ($previousState['running']) {
            $stopPrevious = $this->execute(
                $process,
                ['sudo', 'docker', 'container', 'stop', $rollback],
            );

            if (! $stopPrevious->succeeded()) {
                $this->restoreDockerRollback(
                    $process,
                    $name,
                    $candidate,
                    $rollback,
                );
                $this->throwDockerActivationFailure($process, 'stop-previous-container', $stopPrevious);
            }
        }

        $activation = $this->execute(
            $process,
            ['sudo', 'docker', 'container', 'rename', $candidate, $name],
        );

        if (! $activation->succeeded()) {
            $this->restoreDockerRollback(
                $process,
                $name,
                $candidate,
                $rollback,
            );
            $this->throwDockerActivationFailure($process, 'activate-container', $activation);
        }

        if ($process->desired_state === DesiredProcessState::Running) {
            $start = $this->execute(
                $process,
                ['sudo', 'docker', 'container', 'start', $name],
            );

            if (! $start->succeeded()) {
                $this->rollbackPublishedDockerCandidate(
                    $process,
                    $name,
                    $candidate,
                    $rollback,
                );

                throw new ProcessOperationException(
                    step: 'start',
                    errorCode: 'process.start_failed',
                    message: "Process [{$process->name}] failed to start; the previous container was restored.",
                    result: $this->redactDockerEnvironment($process, $start),
                );
            }
        }

        $finalize = $this->execute(
            $process,
            ['sudo', 'docker', 'container', 'rm', '--force', $rollback],
        );

        if ($finalize->succeeded()) {
            return;
        }

        $this->rollbackPublishedDockerCandidate(
            $process,
            $name,
            $candidate,
            $rollback,
        );
        $this->throwDockerActivationFailure($process, 'finalize-container', $finalize);
    }

    private function restoreDockerRollback(
        #[SensitiveParameter]
        Process $process,
        string $name,
        string $candidate,
        string $rollback,
    ): void {
        $this->restoreDockerRollbackRuntime($process, $name, $rollback);

        $this->removeDockerCandidateAfterFailedActivation($process, $candidate);
    }

    private function restoreDockerRollbackRuntime(
        #[SensitiveParameter]
        Process $process,
        string $name,
        string $rollback,
    ): void {
        $restoreState = $this->execute(
            $process,
            $this->dockerRollbackShouldRun($rollback)
                ? ['sudo', 'docker', 'container', 'start', $rollback]
                : ['sudo', 'docker', 'container', 'stop', $rollback],
        );

        if (! $restoreState->succeeded()) {
            $this->fail(
                $process,
                'restore-container-state',
                'process.docker_recovery_required',
                $restoreState,
            );
        }

        $restore = $this->execute(
            $process,
            ['sudo', 'docker', 'container', 'rename', $rollback, $name],
        );

        if (! $restore->succeeded()) {
            $this->fail($process, 'restore-container', 'process.docker_recovery_required', $restore);
        }
    }

    private function rollbackPublishedDockerCandidate(
        #[SensitiveParameter]
        Process $process,
        string $name,
        string $candidate,
        string $rollback,
    ): void {
        $unpublish = $this->execute(
            $process,
            ['sudo', 'docker', 'container', 'rename', $name, $candidate],
        );

        if (! $unpublish->succeeded()) {
            $this->fail($process, 'unpublish-container', 'process.docker_recovery_required', $unpublish);
        }

        $stopCandidate = $this->execute(
            $process,
            ['sudo', 'docker', 'container', 'stop', $candidate],
        );

        if (! $stopCandidate->succeeded()) {
            $this->fail($process, 'stop-candidate-container', 'process.docker_recovery_required', $stopCandidate);
        }

        $this->restoreDockerRollback(
            $process,
            $name,
            $candidate,
            $rollback,
        );
    }

    private function dockerRollbackShouldRun(string $rollback): bool
    {
        return str_ends_with($rollback, '-rollback-running');
    }

    private function removeDockerCandidateAfterFailedActivation(
        #[SensitiveParameter]
        Process $process,
        string $candidate,
    ): void {
        $cleanup = $this->execute(
            $process,
            ['sudo', 'docker', 'container', 'rm', '--force', $candidate],
        );

        if (! $cleanup->succeeded() && ! $this->isDockerNotFound($cleanup)) {
            $this->fail($process, 'remove-candidate-container', 'process.docker_recovery_required', $cleanup);
        }
    }

    private function throwDockerActivationFailure(
        #[SensitiveParameter]
        Process $process,
        string $step,
        CommandResult $result,
    ): never {
        throw new ProcessOperationException(
            step: $step,
            errorCode: 'process.docker_activation_failed',
            message: "Docker process [{$process->name}] activation failed; the previous container was restored.",
            result: $this->redactDockerEnvironment($process, $result),
        );
    }

    /** @return array{spec: string, running: bool, result: CommandResult}|null */
    private function inspectOwnedDockerContainer(
        #[SensitiveParameter]
        Process $process,
        string $name,
        string $step,
        ?ProcessTarget $target = null,
    ): ?array {
        $inspect = $this->execute(
            $process,
            ['sudo', 'docker', 'container', 'inspect', '--format', self::DOCKER_INSPECT_FORMAT, $name],
            target: $target,
        );

        if ($this->isDockerNotFound($inspect)) {
            return null;
        }

        if (! $inspect->succeeded()) {
            $this->fail($process, $step, 'process.docker_converge_failed', $inspect);
        }

        [$managed, $kind, $ownerId, $specHash, $running] = array_pad(
            explode("\n", trim($inspect->stdout), limit: 5),
            length: 5,
            value: '',
        );

        if (! $this->hasExactDockerOwnership($process, $managed, $kind, $ownerId)) {
            throw new ProcessOperationException(
                step: $step,
                errorCode: 'process.runtime_name_collision',
                message: "Docker container [{$name}] is not owned by this process.",
                result: $inspect,
            );
        }

        if (! in_array($running, ['true', 'false'], strict: true)) {
            throw new ProcessOperationException(
                step: $step,
                errorCode: 'process.docker_converge_failed',
                message: "Docker container [{$name}] returned an invalid running state.",
                result: $inspect,
            );
        }

        return ['spec' => $specHash, 'running' => $running === 'true', 'result' => $inspect];
    }

    private function systemdCandidatePath(#[SensitiveParameter] Process $process): string
    {
        return self::SYSTEMD_CANDIDATE_DIRECTORY.'/'.$this->systemd->unitName($process);
    }

    private function systemdBackupPath(#[SensitiveParameter] Process $process): string
    {
        return self::SYSTEMD_CANDIDATE_DIRECTORY.'/.'.$this->systemd->unitName($process).'.backup';
    }

    private function requireOwnedRuntime(
        #[SensitiveParameter]
        Process $process,
        string $step,
        string $errorCode,
    ): void {
        if ($this->runtimeExistsAndIsOwned($process, $step, $errorCode)) {
            return;
        }

        throw new ProcessOperationException(
            step: $step,
            errorCode: 'process.runtime_not_found',
            message: "Process [{$process->name}] has no native runtime artifact.",
        );
    }

    private function runtimeExistsAndIsOwned(
        #[SensitiveParameter]
        Process $process,
        string $step,
        string $errorCode,
        ?ProcessTarget $target = null,
    ): bool {
        return match ($process->runtime) {
            ProcessRuntime::Systemd => $this->systemdExistsAndIsOwned($process, $step, $errorCode, $target),
            ProcessRuntime::Docker => $this->dockerExistsAndIsOwned($process, $step, $errorCode, $target),
        };
    }

    private function systemdExistsAndIsOwned(
        #[SensitiveParameter]
        Process $process,
        string $step,
        string $errorCode,
        ?ProcessTarget $target = null,
    ): bool {
        $path = $this->systemd->unitPath($process);
        $exists = $this->execute($process, ['sudo', 'test', '-e', $path], target: $target);

        if ($this->isSystemdPathAbsent($exists)) {
            return false;
        }

        if (! $exists->succeeded()) {
            $this->fail($process, $step, $errorCode, $exists);
        }

        $current = $this->execute($process, ['sudo', 'cat', '--', $path], target: $target);

        if ($this->isSystemdNotFound($current)) {
            return false;
        }

        if (! $current->succeeded()) {
            $this->fail($process, $step, $errorCode, $current);
        }

        $ownershipMarker = preg_quote("X-Orbit-Process-ID={$process->id}", delimiter: '/');

        if (preg_match("/^{$ownershipMarker}\\r?$/mD", $current->stdout) === 1) {
            return true;
        }

        throw new ProcessOperationException(
            step: $step,
            errorCode: 'process.runtime_name_collision',
            message: "Systemd unit [{$path}] is not owned by this process.",
            result: $current,
        );
    }

    private function dockerExistsAndIsOwned(
        #[SensitiveParameter]
        Process $process,
        string $step,
        string $errorCode,
        ?ProcessTarget $target = null,
    ): bool {
        $name = $this->docker->containerName($process);
        $inspect = $this->execute(
            $process,
            ['sudo', 'docker', 'container', 'inspect', '--format', self::DOCKER_OWNER_FORMAT, $name],
            target: $target,
        );

        if ($this->isDockerNotFound($inspect)) {
            return false;
        }

        if (! $inspect->succeeded()) {
            $this->fail($process, $step, $errorCode, $inspect);
        }

        [$managed, $kind, $ownerId] = array_pad(
            explode("\n", trim($inspect->stdout), limit: 3),
            length: 3,
            value: '',
        );

        if ($this->hasExactDockerOwnership($process, $managed, $kind, $ownerId)) {
            return true;
        }

        throw new ProcessOperationException(
            step: $step,
            errorCode: 'process.runtime_name_collision',
            message: "Docker container [{$name}] is not owned by this process.",
            result: $inspect,
        );
    }

    private function hasExactDockerOwnership(
        #[SensitiveParameter]
        Process $process,
        string $managed,
        string $kind,
        string $ownerId,
    ): bool {
        return $managed === 'true' && $kind === 'process' && $ownerId === (string) $process->id;
    }

    private function isNativeNotFound(ProcessRuntime $runtime, CommandResult $result): bool
    {
        return match ($runtime) {
            ProcessRuntime::Systemd => $this->isSystemdNotFound($result),
            ProcessRuntime::Docker => $this->isDockerNotFound($result),
        };
    }

    private function isSystemdNotFound(CommandResult $result): bool
    {
        return (
            ! $result->succeeded()
            && (
                str_contains($result->stderr, 'No such file or directory')
                || str_contains($result->stderr, 'could not be found')
                || str_contains($result->stderr, 'not found')
            )
        );
    }

    private function isSystemdPathAbsent(CommandResult $result): bool
    {
        return $result->exitCode === 1 && trim($result->stdout) === '' && trim($result->stderr) === '';
    }

    private function isDockerNotFound(CommandResult $result): bool
    {
        return (
            ! $result->succeeded()
            && (str_contains($result->stderr, 'No such object') || str_contains($result->stderr, 'No such container'))
        );
    }

    /** @param non-empty-list<string> $arguments */
    private function restoreSystemdUnit(#[SensitiveParameter] Process $process, array $arguments): void
    {
        $restore = $this->execute($process, $arguments);

        if (! $restore->succeeded()) {
            $this->fail($process, 'restore-unit', 'process.systemd_rollback_failed', $restore);
        }

        $reload = $this->execute($process, ['sudo', 'systemctl', 'daemon-reload']);

        if (! $reload->succeeded()) {
            $this->fail($process, 'rollback-daemon-reload', 'process.systemd_rollback_failed', $reload);
        }
    }

    /** @param non-empty-list<string> $arguments */
    private function execute(
        #[SensitiveParameter]
        Process $process,
        array $arguments,
        #[SensitiveParameter]
        ?string $input = null,
        #[SensitiveParameter]
        ?ProtectedInput $protectedInput = null,
        ?ProcessTarget $target = null,
    ): CommandResult {
        try {
            $target ??= $this->targets->forProcess($process);

            if (! is_string($target->node->wireguard_address) || $target->node->wireguard_address === '') {
                throw new ProcessOperationException(
                    step: 'ssh',
                    errorCode: 'process.wireguard_address_missing',
                    message: "Node [{$target->node->name}] has no WireGuard address.",
                );
            }

            return $this->ssh->execute(
                new SshConnection(
                    host: $target->node->wireguard_address,
                    user: 'orbit',
                    port: 22,
                    identityFile: $this->keys->privateKeyPath(),
                    knownHostsFile: $this->knownHosts->path(),
                ),
                new RemoteCommand($arguments, $input, $protectedInput),
            );
        } finally {
            $protectedInput?->close();
        }
    }

    /** @param non-empty-list<string> $arguments */
    private function executeSuccessfully(
        #[SensitiveParameter]
        Process $process,
        array $arguments,
        string $step,
        string $errorCode,
        #[SensitiveParameter]
        ?string $input = null,
        #[SensitiveParameter]
        ?ProtectedInput $protectedInput = null,
        ?ProcessTarget $target = null,
    ): CommandResult {
        $result = $this->execute($process, $arguments, $input, $protectedInput, $target);

        if ($result->succeeded()) {
            return $result;
        }

        $this->fail($process, $step, $errorCode, $result);
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
            message: "Process [{$process->name}] runtime step [{$step}] failed.",
            result: $this->redactDockerEnvironment($process, $result),
        );
    }

    /** @mago-expect analysis:mixed-assignment Persisted JSON values start at an untyped boundary. */
    private function redactDockerEnvironment(
        #[SensitiveParameter]
        Process $process,
        #[SensitiveParameter]
        CommandResult $result,
    ): CommandResult {
        if ($process->runtime !== ProcessRuntime::Docker) {
            return $result;
        }

        $environment = $process->runtime_config['environment'] ?? null;

        if (! is_array($environment)) {
            return $result;
        }

        $values = [];

        foreach ($environment as $value) {
            if (! is_string($value) || $value === '') {
                continue;
            }

            $values[] = $value;
        }

        $values = array_values(array_unique($values));
        usort($values, static fn (string $first, string $second): int => strlen($second) <=> strlen($first));

        return new CommandResult(
            exitCode: $result->exitCode,
            stdout: str_replace(search: $values, replace: '[REDACTED]', subject: $result->stdout),
            stderr: str_replace(search: $values, replace: '[REDACTED]', subject: $result->stderr),
            durationMs: $result->durationMs,
            truncated: $result->truncated,
        );
    }
}
