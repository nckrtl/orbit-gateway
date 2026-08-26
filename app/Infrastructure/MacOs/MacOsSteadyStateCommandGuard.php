<?php

declare(strict_types=1);

namespace App\Infrastructure\MacOs;

use App\Infrastructure\Ssh\RemoteCommand;
use SensitiveParameter;
use UnexpectedValueException;

final readonly class MacOsSteadyStateCommandGuard
{
    /** @var list<string> */
    private const array PROTECTED_TARGETS = [
        '/etc/pf.anchors/com.orbit.app-dev',
        '/etc/pf.conf',
        '/Library/Application Support/Orbit/app-dev/dnsmasq.conf',
        '/Library/LaunchDaemons/com.orbit.dnsmasq.plist',
        '/etc/resolver',
        'system/com.orbit.dnsmasq',
        '/usr/sbin/systemsetup',
    ];

    public function guard(#[SensitiveParameter] RemoteCommand $command): RemoteCommand
    {
        $surfaces = [...$command->arguments];

        if ($command->input !== null) {
            $surfaces[] = $command->input;
        }

        foreach ($surfaces as $surface) {
            if (preg_match('/(?:\A|[\s\/])sudo(?:\z|\s)/', $surface) === 1) {
                throw $this->unsafeCommand();
            }

            foreach (self::PROTECTED_TARGETS as $protectedTarget) {
                if (str_contains($surface, $protectedTarget)) {
                    throw $this->unsafeCommand();
                }
            }
        }

        return $command;
    }

    private function unsafeCommand(): UnexpectedValueException
    {
        return new UnexpectedValueException(
            'Darwin steady-state commands cannot use sudo or protected paths.',
        );
    }
}
