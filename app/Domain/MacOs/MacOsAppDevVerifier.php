<?php

declare(strict_types=1);

namespace App\Domain\MacOs;

use App\Models\Node;

interface MacOsAppDevVerifier
{
    public function verify(Node $node): void;
}
