<?php

declare(strict_types=1);

namespace Tests\Support;

use App\Infrastructure\Processes\CommandResult;
use App\Infrastructure\Ssh\RemoteCommand;
use Illuminate\Filesystem\Filesystem;
use Symfony\Component\Process\Process;

final class FpmPublishHarness
{
    private string $root;

    private Filesystem $files;

    public function __construct()
    {
        $this->root = sys_get_temp_dir().'/orbit-fpm-publish-'.bin2hex(random_bytes(8));
        $this->files = new Filesystem;
        $this->files->ensureDirectoryExists(path: $this->root.'/bin', mode: 0o777);
        $this->files->ensureDirectoryExists(path: $this->lockDirectory(), mode: 0o777);
        $this->files->ensureDirectoryExists(path: $this->logDirectory(), mode: 0o777);
        $this->writeShims();
    }

    public function phpRoot(): string
    {
        return $this->root.'/php';
    }

    public function lockDirectory(): string
    {
        return $this->root.'/locks';
    }

    public function logDirectory(): string
    {
        return $this->root.'/logs';
    }

    public function prepare(string $version, string $managedFilename, string $previous): string
    {
        $poolDirectory = "{$this->phpRoot()}/{$version}/fpm/pool.d";
        $this->files->ensureDirectoryExists(path: $poolDirectory, mode: 0o777);
        $this->files->put(
            "{$this->phpRoot()}/{$version}/fpm/php-fpm.conf",
            "include={$poolDirectory}/*.conf\n",
        );
        $managed = "{$poolDirectory}/{$managedFilename}";
        $this->files->put($managed, $previous);
        chmod(filename: $managed, permissions: 0o600);

        return $managed;
    }

    public function run(RemoteCommand $command): CommandResult
    {
        $process = new Process(array_slice(array: $command->arguments, offset: 1), $this->root, [
            'PATH' => $this->root.'/bin:'.getenv('PATH'),
            'HARNESS_SERVICE_LOG' => $this->root.'/systemctl.log',
            'HARNESS_ACTIVATION_MARKER' => $this->root.'/activation-failed',
        ]);
        $process->setInput($command->input);
        $process->run();

        return new CommandResult(
            exitCode: $process->getExitCode() ?? 1,
            stdout: $process->getOutput(),
            stderr: $process->getErrorOutput(),
            durationMs: 1,
            truncated: false,
        );
    }

    /** @return list<string> */
    public function serviceCalls(): array
    {
        $path = $this->root.'/systemctl.log';

        if (! is_file($path)) {
            return [];
        }

        $contents = file_get_contents($path);

        if ($contents === false) {
            return [];
        }

        return array_values(array_filter(explode("\n", trim($contents))));
    }

    public function cleanup(): void
    {
        $this->files->deleteDirectory($this->root);
    }

    private function writeShims(): void
    {
        $this->files->put($this->root.'/bin/sudo', "#!/usr/bin/env bash\nexec \"\$@\"\n");
        $this->files->put(
            $this->root.'/bin/install',
            <<<'BASH'
                #!/usr/bin/env bash
                set -euo pipefail
                args=()
                skip_next=0

                for arg in "$@"; do
                    if [ "$skip_next" = 1 ]; then
                        skip_next=0
                        continue
                    fi

                    case "$arg" in
                        -o|-g)
                            skip_next=1
                            ;;
                        *)
                            args+=("$arg")
                            ;;
                    esac
                done

                exec /usr/bin/install "${args[@]}"
                BASH,
        );
        $this->files->put(
            $this->root.'/bin/php-fpm8.5',
            <<<'BASH'
                #!/usr/bin/env bash
                set -euo pipefail
                test "$1" = -y
                test -f "$2"
                test "$3" = -t
                BASH,
        );
        $this->files->put(
            $this->root.'/bin/systemctl',
            <<<'BASH'
                #!/usr/bin/env bash
                set -euo pipefail
                printf '%s\n' "$*" >> "${HARNESS_SERVICE_LOG}"

                if [ "$1" = reload-or-restart ] && [ ! -e "${HARNESS_ACTIVATION_MARKER}" ]; then
                    touch "${HARNESS_ACTIVATION_MARKER}"
                    exit 1
                fi

                exit 0
                BASH,
        );

        chmod(filename: $this->root.'/bin/sudo', permissions: 0o755);
        chmod(filename: $this->root.'/bin/install', permissions: 0o755);
        chmod(filename: $this->root.'/bin/php-fpm8.5', permissions: 0o755);
        chmod(filename: $this->root.'/bin/systemctl', permissions: 0o755);
    }
}
