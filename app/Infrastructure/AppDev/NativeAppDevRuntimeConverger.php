<?php

declare(strict_types=1);

namespace App\Infrastructure\AppDev;

use App\Domain\AppDev\AppDevCaddyManager;
use App\Domain\AppDev\AppDevCertificateManager;
use App\Domain\AppDev\AppDevPhpFpmManager;
use App\Domain\AppDev\AppDevRuntimeConverger;
use App\Domain\AppDev\AppDevSourceManager;
use App\Domain\AppDev\PrivateDnsManager;
use App\Models\Instance;
use App\Models\Workspace;

final readonly class NativeAppDevRuntimeConverger implements AppDevRuntimeConverger
{
    public function __construct(
        private AppDevSourceManager $source,
        private AppDevPhpFpmManager $phpFpm,
        private AppDevCertificateManager $certificates,
        private AppDevCaddyManager $caddy,
        private PrivateDnsManager $dns,
    ) {}

    public function convergeInstance(Instance $instance): void
    {
        $this->source->convergeInstance($instance);
        $this->phpFpm->converge($instance->node);
        $this->certificates->convergeInstance($instance);
        $this->caddy->converge($instance->node);
        $this->dns->converge();
    }

    public function removeInstance(Instance $instance): void
    {
        $this->unpublishInstance($instance);
        $this->source->removeInstance($instance);
    }

    public function unpublishInstance(Instance $instance): void
    {
        $this->caddy->converge($instance->node);
        $this->phpFpm->converge($instance->node);
        $this->dns->converge();
        $this->certificates->removeInstance($instance);
    }

    public function convergeWorkspace(Workspace $workspace): void
    {
        $this->source->convergeWorkspace($workspace);
        $this->phpFpm->converge($workspace->instance->node);
        $this->certificates->convergeWorkspace($workspace);
        $this->caddy->converge($workspace->instance->node);
        $this->dns->converge();
    }

    public function removeWorkspace(Workspace $workspace): void
    {
        $this->unpublishWorkspace($workspace);
        $this->source->removeWorkspace($workspace);
    }

    public function unpublishWorkspace(Workspace $workspace): void
    {
        $this->caddy->converge($workspace->instance->node);
        $this->phpFpm->converge($workspace->instance->node);
        $this->dns->converge();
        $this->certificates->removeWorkspace($workspace);
    }
}
