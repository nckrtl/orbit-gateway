<?php

declare(strict_types=1);

namespace Tests\Support;

use App\Infrastructure\AppDev\AppDevCaddyPublisher;
use Illuminate\Filesystem\Filesystem;
use Symfony\Component\Process\Process;

final class AppDevCaddyPublishHarness
{
    private string $root;

    private Filesystem $files;

    public function __construct()
    {
        $this->root = sys_get_temp_dir().'/orbit-app-dev-caddy-'.bin2hex(random_bytes(8));
        $this->files = new Filesystem;
    }

    public function etcCaddyPath(string $suffix = ''): string
    {
        $path = $this->root.'/etc/caddy';

        if ($suffix === '') {
            return $path;
        }

        return $path.'/'.$suffix;
    }

    public function run(AppDevCaddyPublisher $publisher, AppDevCaddyPublishScenario $scenario): AppDevCaddyPublishResult
    {
        $this->resetFilesystem();

        $liveMainPath = $this->etcCaddyPath('Caddyfile');
        $versionsDirectory = $this->etcCaddyPath('orbit-versions');
        $this->prepareLiveConfiguration($scenario, $liveMainPath, $versionsDirectory);
        $this->writeShims($scenario);

        $command = $publisher->command("# Managed by Orbit.\n", 'test-version');
        $process = new Process(array_slice(array: $command->arguments, offset: 1), $this->root, [
            'PATH' => $this->root.'/bin:'.getenv('PATH'),
            'HARNESS_PACKAGE_DEFAULT_MD5' => $scenario->packageDefault === null ? '' : md5($scenario->packageDefault),
            'HARNESS_VALIDATE_LOG' => $this->root.'/validate.log',
            'HARNESS_FAIL_VALIDATION' => $scenario->failValidation ? '1' : '0',
        ]);
        $process->setInput($command->input);
        $process->run();

        $liveMainAfter = file_get_contents($liveMainPath);

        return new AppDevCaddyPublishResult(
            exitCode: $process->getExitCode() ?? 1,
            stdout: $process->getOutput(),
            stderr: $process->getErrorOutput(),
            liveMainAfter: $liveMainAfter === false ? '' : $liveMainAfter,
            publishedFragments: $this->publishedFragments($versionsDirectory.'/test-version/fragments'),
        );
    }

    public function cleanup(): void
    {
        $this->files->deleteDirectory($this->root);
    }

    private function resetFilesystem(): void
    {
        $this->cleanup();
        $this->files->ensureDirectoryExists(path: $this->root, mode: 0o777);
        $this->files->ensureDirectoryExists(path: $this->etcCaddyPath(), mode: 0o777);
        $this->files->ensureDirectoryExists(path: $this->root.'/bin', mode: 0o777);
    }

    private function prepareLiveConfiguration(
        AppDevCaddyPublishScenario $scenario,
        string $liveMainPath,
        string $versionsDirectory,
    ): void {
        $liveMainDirectory = dirname($liveMainPath);

        $this->files->ensureDirectoryExists(path: $liveMainDirectory, mode: 0o777);

        if (! $scenario->liveIsOrbitAggregate) {
            file_put_contents(filename: $liveMainPath, data: $scenario->liveMain);

            return;
        }

        $currentVersion = $versionsDirectory.'/current';
        $this->files->ensureDirectoryExists(path: $currentVersion.'/fragments', mode: 0o777);
        file_put_contents(filename: $currentVersion.'/Caddyfile', data: $scenario->liveMain);

        foreach ($scenario->existingOrbitFragments as $name => $contents) {
            file_put_contents(filename: $currentVersion.'/fragments/'.$name, data: $contents);
        }

        $link = new Process(['ln', '-sfn', $currentVersion.'/Caddyfile', $liveMainPath]);
        $link->run();

        if (! $link->isSuccessful()) {
            throw new \RuntimeException($link->getErrorOutput());
        }
    }

    private function writeShims(AppDevCaddyPublishScenario $scenario): void
    {
        file_put_contents(
            filename: $this->root.'/bin/sudo',
            data: "#!/usr/bin/env bash\nprintf 'unexpected nested sudo\\n' >&2\nexit 97\n",
        );
        file_put_contents(
            filename: $this->root.'/bin/install',
            data: <<<'BASH'
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
        file_put_contents(
            filename: $this->root.'/bin/dpkg-query',
            data: "#!/usr/bin/env bash\nprintf '%s %s\\n' "
            .escapeshellarg($this->etcCaddyPath('Caddyfile'))
            .' "'
            .($scenario->packageDefault === null ? '' : md5($scenario->packageDefault))
            ."\"\n",
        );
        file_put_contents(
            filename: $this->root.'/bin/caddy',
            data: "#!/usr/bin/env bash\nprintf 'validate %s\\n' \"\$*\" >> \"\${HARNESS_VALIDATE_LOG}\"\nif [ \"\${HARNESS_FAIL_VALIDATION}\" = 1 ]; then\n  exit 1\nfi\nexit 0\n",
        );
        file_put_contents(filename: $this->root.'/bin/systemctl', data: "#!/usr/bin/env bash\nexit 0\n");
        file_put_contents(filename: $this->root.'/bin/chown', data: "#!/usr/bin/env bash\nexit 0\n");

        chmod($this->root.'/bin/sudo', permissions: 0o755);
        chmod($this->root.'/bin/install', permissions: 0o755);
        chmod($this->root.'/bin/dpkg-query', permissions: 0o755);
        chmod($this->root.'/bin/caddy', permissions: 0o755);
        chmod($this->root.'/bin/systemctl', permissions: 0o755);
        chmod($this->root.'/bin/chown', permissions: 0o755);
    }

    /** @return array<string, string> */
    private function publishedFragments(string $directory): array
    {
        if (! is_dir($directory)) {
            return [];
        }

        return collect($this->files->files($directory))
            ->mapWithKeys(static function (\SplFileInfo $file): array {
                $contents = file_get_contents($file->getPathname());

                return [$file->getFilename() => $contents === false ? '' : $contents];
            })
            ->all();
    }
}
