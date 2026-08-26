<?php

declare(strict_types=1);

namespace Tests\Support;

use App\Domain\MacOs\MacOsAppDevVerifier;
use App\Domain\Shared\ResourceOperationException;
use App\Models\Node;

final class NodeRoleSetupFakeVerifier implements MacOsAppDevVerifier
{
    public int $calls = 0;

    public ?ResourceOperationException $failure = null;

    public function verify(Node $node): void
    {
        $this->calls++;

        if ($this->failure instanceof ResourceOperationException) {
            throw $this->failure;
        }
    }
}
