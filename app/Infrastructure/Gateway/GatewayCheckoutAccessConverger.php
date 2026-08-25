<?php

declare(strict_types=1);

namespace App\Infrastructure\Gateway;

use App\Domain\Nodes\NodeProvisioningException;
use App\Infrastructure\Processes\CommandResult;
use App\Infrastructure\Processes\ProcessInvocation;
use App\Infrastructure\Processes\ProcessRunner;

final readonly class GatewayCheckoutAccessConverger
{
    public function __construct(
        private ProcessRunner $processes,
        private string $checkoutPath,
    ) {}

    public function converge(): void
    {
        $this->validate();
        $directories = $this->ancestors();
        $this->run('gateway-checkout-access', 'gateway.checkout_access_failed', [
            'sudo',
            'chown',
            'orbit:caddy',
            ...$directories,
            $this->checkoutPath.'/public',
        ]);
        $this->run('gateway-checkout-access', 'gateway.checkout_access_failed', [
            'sudo',
            'chmod',
            '0710',
            ...$directories,
        ]);
        $this->run('gateway-checkout-access', 'gateway.checkout_access_failed', [
            'sudo',
            'chmod',
            '0750',
            $this->checkoutPath.'/public',
        ]);
        $this->run('gateway-environment-protect', 'gateway.environment_protection_failed', [
            'sudo',
            'chmod',
            '0600',
            $this->checkoutPath.'/.env',
        ]);
    }

    private function validate(): void
    {
        $components = explode('/', $this->checkoutPath);

        if (
            rtrim(string: $this->checkoutPath, characters: '/') !== $this->checkoutPath
            || ! str_starts_with($this->checkoutPath, '/home/orbit/')
            || str_contains($this->checkoutPath, "\0")
            || str_contains($this->checkoutPath, "\n")
            || in_array(needle: '..', haystack: $components, strict: true)
            || in_array(needle: '.', haystack: $components, strict: true)
        ) {
            throw $this->failure(
                'gateway-checkout-validate',
                'gateway.checkout_invalid',
                "Gateway checkout path [{$this->checkoutPath}] is unsafe.",
            );
        }

        $this->run(
            step: 'gateway-checkout-validate',
            errorCode: 'gateway.checkout_invalid',
            arguments: ['sudo', 'bash', '-seu', '--', $this->checkoutPath],
            input: <<<'BASH'
                checkout=$1
                resolved=$(readlink -f -- "$checkout")

                if [ "$resolved" != "$checkout" ]; then
                    exit 1
                fi

                case "$resolved" in
                    /home/orbit/*) ;;
                    *) exit 1 ;;
                esac

                test -d "$resolved/public"
                test -f "$resolved/.env"
                BASH,
        );
    }

    /** @return non-empty-list<string> */
    private function ancestors(): array
    {
        $relative = substr($this->checkoutPath, strlen('/home/orbit/'));
        $directories = ['/home/orbit'];
        $path = '/home/orbit';

        foreach (explode('/', $relative) as $component) {
            $path .= "/{$component}";
            $directories[] = $path;
        }

        return $directories;
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
            throw $this->failure($step, $errorCode, "Gateway checkout convergence step [{$step}] failed.", $result);
        }
    }

    private function failure(
        string $step,
        string $errorCode,
        string $message,
        ?CommandResult $result = null,
    ): NodeProvisioningException {
        return new NodeProvisioningException(
            step: $step,
            errorCode: $errorCode,
            message: $message,
            result: $result,
        );
    }
}
