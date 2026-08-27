<?php

declare(strict_types=1);

namespace App\Infrastructure\AppProd;

use App\Domain\AppProd\AppProdCaddyManager;
use App\Domain\AppProd\AppProdPhpFpmManager;
use App\Domain\AppProd\AppProdRuntimeConverger;
use App\Domain\AppProd\AppProdSourceManager;
use App\Domain\AppProd\AppProdUserManager;
use App\Models\Instance;

final readonly class NativeAppProdRuntimeConverger implements AppProdRuntimeConverger
{
    public function __construct(
        private AppProdUserManager $users,
        private AppProdSourceManager $source,
        private AppProdPhpFpmManager $phpFpm,
        private AppProdCaddyManager $caddy,
    ) {}

    public function convergeInstance(Instance $instance): void
    {
        $this->users->converge($instance);
        $this->source->converge($instance);
        $this->phpFpm->converge($instance->node);
        $this->caddy->converge($instance->node);
    }

    public function removeInstance(Instance $instance): void
    {
        $this->unpublishInstance($instance);
        $this->source->remove($instance);
        $this->users->remove($instance);
    }

    public function unpublishInstance(Instance $instance): void
    {
        $this->caddy->converge($instance->node);
        $this->phpFpm->converge($instance->node);
    }
}
