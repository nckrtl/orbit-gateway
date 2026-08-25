<?php

declare(strict_types=1);

namespace App\Domain\AppDev;

use Closure;

interface AppDevSourceOperationLock
{
    /**
     * @template T
     *
     * @param Closure(): T $operation
     * @return T
     */
    public function synchronized(int $nodeId, Closure $operation): mixed;
}
