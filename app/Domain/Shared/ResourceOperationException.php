<?php

declare(strict_types=1);

namespace App\Domain\Shared;

use RuntimeException;

/** @mago-expect lint:cyclomatic-complexity Stable error details use explicit per-code allowlists. */
class ResourceOperationException extends RuntimeException
{
    /** @var array<string, bool|int|string|null> */
    public readonly array $safeDetails;

    /** @param array<string, bool|int|string|null> $safeDetails */
    public function __construct(
        public readonly string $errorCode,
        string $message,
        public readonly int $status = 422,
        array $safeDetails = [],
    ) {
        $this->safeDetails = $this->sanitizeDetails($errorCode, $safeDetails);
        parent::__construct($message);
    }

    /**
     * @param array<string, bool|int|string|null> $details
     * @return array<string, bool|int|string|null>
     */
    private function sanitizeDetails(string $errorCode, array $details): array
    {
        if ($errorCode === 'macos.verification_failed') {
            $allowed = [
                'ssh-host-key',
                'identity',
                'architecture',
                'restricted-key',
                'homebrew',
                'toolchain',
                'caddy',
                'php-fpm',
            ];

            return (
                in_array(needle: $details['check'] ?? null, haystack: $allowed, strict: true)
                    ? ['check' => $details['check']]
                    : []
            );
        }

        if ($errorCode === 'macos.local_action_required') {
            $allowed = ['remote-login', 'pf-anchor', 'resolver', 'dnsmasq', 'root-ca-trust'];
            $check = $details['check'] ?? null;

            if (! is_string($check) || ! in_array(needle: $check, haystack: $allowed, strict: true)) {
                return [];
            }

            return [
                'check' => $check,
                'local_command' => $check === 'root-ca-trust' ? 'orbit gateway:trust' : null,
            ];
        }

        if ($errorCode === 'macos.user_session_unavailable') {
            return ($details['runtime'] ?? null) === 'launchd' ? ['runtime' => 'launchd'] : [];
        }

        if ($errorCode === 'node.role_setup_not_ready') {
            $failedStep = $details['failed_step'] ?? null;

            if (
                ! is_string($failedStep)
                || ! in_array(needle: $failedStep, haystack: ['wireguard-projection', 'private-dns'], strict: true)
            ) {
                return [];
            }

            return [
                'failed_step' => $failedStep,
                'local_action_required' => false,
                'local_command' => null,
            ];
        }

        if ($errorCode === 'macos.setup_failed' && ($details['failed_step'] ?? null) === 'local-setup') {
            return ['failed_step' => 'local-setup'];
        }

        return [];
    }
}
