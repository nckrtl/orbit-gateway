<?php

declare(strict_types=1);

namespace App\Infrastructure\Gateway;

use App\Domain\Nodes\NodeProvisioningException;
use App\Infrastructure\Processes\ProcessInvocation;
use App\Infrastructure\Processes\ProcessRunner;

final readonly class NativeGatewayFpmConverger
{
    private const string CANDIDATE_DIRECTORY = '/etc/php/8.5/fpm/orbit-candidate.d';

    private const string CANDIDATE_MAIN = '/etc/php/8.5/fpm/orbit-gateway-candidate.conf';

    private const string CANDIDATE_POOL = '/etc/php/8.5/fpm/orbit-candidate.d/orbit-gateway.conf';

    private const string LIVE_POOL = '/etc/php/8.5/fpm/pool.d/orbit-gateway.conf';

    public function __construct(
        private ProcessRunner $processes,
    ) {}

    public function converge(string $generatedPool): void
    {
        try {
            $this->stage($generatedPool);
            $this->run(
                step: 'gateway-fpm-validate',
                errorCode: 'gateway.fpm_config_invalid',
                arguments: ['sudo', 'php-fpm8.5', '--test', '--fpm-config', self::CANDIDATE_MAIN],
            );
            $this->run(
                step: 'gateway-fpm-install',
                errorCode: 'gateway.fpm_config_install_failed',
                arguments: ['sudo', 'mv', '-f', '--', self::CANDIDATE_POOL, self::LIVE_POOL],
            );
            $this->cleanup();
        } catch (NodeProvisioningException $exception) {
            $this->cleanup();

            throw $exception;
        }

        $this->run(
            step: 'gateway-fpm-enable',
            errorCode: 'gateway.fpm_start_failed',
            arguments: ['sudo', 'systemctl', 'enable', 'php8.5-fpm'],
        );
        $this->run(
            step: 'gateway-fpm-reload',
            errorCode: 'gateway.fpm_start_failed',
            arguments: ['sudo', 'systemctl', 'reload-or-restart', 'php8.5-fpm'],
        );
    }

    private function stage(string $generatedPool): void
    {
        $this->run(
            step: 'gateway-fpm-stage',
            errorCode: 'gateway.fpm_config_install_failed',
            arguments: ['sudo', 'bash', '-seu', '--', $generatedPool],
            input: <<<'BASH'
                replacement=$1
                candidate_directory=/etc/php/8.5/fpm/orbit-candidate.d
                candidate_main=/etc/php/8.5/fpm/orbit-gateway-candidate.conf
                live_main=/etc/php/8.5/fpm/php-fpm.conf
                rm -rf -- "$candidate_directory"
                install -d -o root -g root -m 0755 "$candidate_directory"

                for pool in /etc/php/8.5/fpm/pool.d/*.conf; do
                    if [ ! -e "$pool" ]; then
                        continue
                    fi

                    pool_name=$(basename "$pool")
                    if [ "$pool_name" = orbit-gateway.conf ]; then
                        continue
                    fi

                    cp --preserve=mode,ownership -- "$pool" "$candidate_directory/$pool_name"
                done

                install -o root -g root -m 0644 -- "$replacement" "$candidate_directory/orbit-gateway.conf"
                awk '
                    BEGIN { replacement_count = 0 }
                    /^[[:space:]]*include[[:space:]]*=[[:space:]]*\/etc\/php\/8\.5\/fpm\/pool\.d\/\*\.conf[[:space:]]*$/ {
                        print "include = /etc/php/8.5/fpm/orbit-candidate.d/*.conf"
                        replacement_count++
                        next
                    }
                    { print }
                    END { if (replacement_count != 1) exit 1 }
                ' "$live_main" > "$candidate_main"
                chown root:root "$candidate_main"
                chmod 0644 "$candidate_main"
                BASH,
        );
    }

    private function cleanup(): void
    {
        $this->processes->run(new ProcessInvocation([
            'sudo',
            'rm',
            '-rf',
            '--',
            self::CANDIDATE_DIRECTORY,
            self::CANDIDATE_MAIN,
        ]));
    }

    /** @param non-empty-list<string> $arguments */
    private function run(string $step, string $errorCode, array $arguments, ?string $input = null): void
    {
        $result = $this->processes->run(new ProcessInvocation(
            arguments: $arguments,
            timeout: 60.0,
            input: $input,
        ));

        if (! $result->succeeded()) {
            throw new NodeProvisioningException(
                step: $step,
                errorCode: $errorCode,
                message: "Gateway FPM convergence step [{$step}] failed.",
                result: $result,
            );
        }
    }
}
