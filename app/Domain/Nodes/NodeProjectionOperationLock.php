<?php

declare(strict_types=1);

namespace App\Domain\Nodes;

use Closure;

interface NodeProjectionOperationLock
{
    /**
     * @template TReturn
     *
     * @param Closure(): TReturn $operation
     * @return TReturn
     */
    public function synchronized(Closure $operation): mixed;
}
