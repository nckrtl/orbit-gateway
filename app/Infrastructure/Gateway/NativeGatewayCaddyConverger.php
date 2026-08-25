<?php

declare(strict_types=1);

namespace App\Infrastructure\Gateway;

use App\Domain\Nodes\NodeProvisioningException;
use App\Infrastructure\Processes\ProcessInvocation;
use App\Infrastructure\Processes\ProcessRunner;

final readonly class NativeGatewayCaddyConverger
{
    public function __construct(
        private ProcessRunner $processes,
    ) {}

    public function converge(string $generatedCaddy): void
    {
        $version = bin2hex(random_bytes(8));
        $candidateDirectory = "/etc/caddy/orbit-versions/{$version}.candidate";
        $versionDirectory = "/etc/caddy/orbit-versions/{$version}";
        $candidateLink = "/etc/caddy/Caddyfile.orbit-candidate.{$version}";

        try {
            $this->stage($generatedCaddy, $candidateDirectory, $versionDirectory);
            $this->run(
                step: 'gateway-caddy-validate',
                errorCode: 'gateway.caddy_config_invalid',
                arguments: [
                    'sudo',
                    'caddy',
                    'validate',
                    '--config',
                    $versionDirectory.'/Caddyfile',
                    '--adapter',
                    'caddyfile',
                ],
            );
            $this->run(
                step: 'gateway-caddy-publish',
                errorCode: 'gateway.caddy_config_install_failed',
                arguments: ['sudo', 'ln', '-s', '--', $versionDirectory.'/Caddyfile', $candidateLink],
            );
            $this->run(
                step: 'gateway-caddy-publish',
                errorCode: 'gateway.caddy_config_install_failed',
                arguments: ['sudo', 'mv', '-Tf', '--', $candidateLink, '/etc/caddy/Caddyfile'],
            );
        } catch (NodeProvisioningException $exception) {
            $this->cleanup([$candidateDirectory, $versionDirectory, $candidateLink]);

            throw $exception;
        }

        $this->run(
            step: 'gateway-caddy-enable',
            errorCode: 'gateway.caddy_start_failed',
            arguments: ['sudo', 'systemctl', 'enable', 'caddy'],
        );
        $this->run(
            step: 'gateway-caddy-reload',
            errorCode: 'gateway.caddy_start_failed',
            arguments: ['sudo', 'systemctl', 'reload-or-restart', 'caddy'],
        );
    }

    private function stage(string $generatedCaddy, string $candidateDirectory, string $versionDirectory): void
    {
        $this->run(
            step: 'gateway-caddy-stage',
            errorCode: 'gateway.caddy_config_install_failed',
            arguments: ['sudo', 'bash', '-seu', '--', $generatedCaddy, $candidateDirectory, $versionDirectory],
            input: <<<'BASH'
                gateway_fragment=$1
                candidate_directory=$2
                version_directory=$3
                versions_directory=/etc/caddy/orbit-versions
                rm -rf -- "$candidate_directory"
                install -d -o root -g root -m 0755 "$versions_directory" "$candidate_directory/fragments"
                source_main=$(readlink -f /etc/caddy/Caddyfile)
                test -f "$source_main"
                previous_fragments=$(dirname "$source_main")/fragments

                if [ -d "$previous_fragments" ]; then
                    for fragment in "$previous_fragments"/*.caddy; do
                        if [ ! -e "$fragment" ] || [ "$(basename "$fragment")" = gateway.caddy ]; then
                            continue
                        fi

                        cp --preserve=mode,ownership -- "$fragment" "$candidate_directory/fragments/"
                    done
                elif [ -d /etc/caddy/orbit.d ]; then
                    for fragment in /etc/caddy/orbit.d/*.caddy; do
                        if [ ! -e "$fragment" ] || [ "$(basename "$fragment")" = gateway.caddy ]; then
                            continue
                        fi

                        cp --preserve=mode,ownership -- "$fragment" "$candidate_directory/fragments/"
                    done
                fi

                install -o root -g root -m 0644 -- "$gateway_fragment" "$candidate_directory/fragments/gateway.caddy"
                printf 'import %s/fragments/*.caddy\n' "$version_directory" > "$candidate_directory/Caddyfile"
                chown -R root:root "$candidate_directory"
                find "$candidate_directory" -type d -exec chmod 0755 {} +
                find "$candidate_directory" -type f -exec chmod 0644 {} +
                mv -f -- "$candidate_directory" "$version_directory"
                BASH,
        );
    }

    /** @param non-empty-list<string> $paths */
    private function cleanup(array $paths): void
    {
        $this->processes->run(new ProcessInvocation(['sudo', 'rm', '-rf', '--', ...$paths]));
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
                message: "Gateway Caddy convergence step [{$step}] failed.",
                result: $result,
            );
        }
    }
}
