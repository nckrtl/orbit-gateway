<?php

declare(strict_types=1);

namespace App\Domain\MacOs;

use App\Domain\Shared\ResourceOperationException;

final class MacOsProtectedDriftException extends ResourceOperationException
{
    public function __construct(MacOsProtectedCheck $check, ?MacOsLocalActionCommand $command = null)
    {
        $approvedCommand =
            $check === MacOsProtectedCheck::RootCaTrust && $command === MacOsLocalActionCommand::GatewayTrust
                ? $command->value
                : null;

        parent::__construct(
            errorCode: 'macos.local_action_required',
            message: "Protected macOS state [{$check->value}] needs a local action.",
            status: 409,
            safeDetails: [
                'check' => $check->value,
                'local_command' => $approvedCommand,
            ],
        );
    }
}
