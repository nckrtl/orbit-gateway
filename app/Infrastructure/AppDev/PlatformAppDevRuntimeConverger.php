<?php

declare(strict_types=1);

namespace App\Infrastructure\AppDev;

use App\Domain\AppDev\AppDevCaddyManager;
use App\Domain\AppDev\AppDevCertificateManager;
use App\Domain\AppDev\AppDevPhpFpmManager;
use App\Domain\AppDev\AppDevRuntimeConverger;
use App\Domain\AppDev\AppDevSourceManager;
use App\Models\Instance;
use App\Models\Workspace;

final readonly class PlatformAppDevRuntimeConverger implements AppDevRuntimeConverger
{
    public function __construct(
        private AppDevRuntimeConverger $linux,
        private AppDevSourceManager $darwinSource,
        private AppDevPhpFpmManager $darwinPhpFpm,
        private AppDevCertificateManager $darwinCertificates,
        private AppDevCaddyManager $darwinCaddy,
    ) {}

    public function convergeInstance(Instance $instance): void
    {
        if ($instance->node->platform !== 'darwin') {
            $this->linux->convergeInstance($instance);

            return;
        }

        $this->darwinSource->convergeInstance($instance);
        $this->darwinPhpFpm->converge($instance->node);
        $this->darwinCertificates->convergeInstance($instance);
        $this->darwinCaddy->converge($instance->node);
    }

    public function removeInstance(Instance $instance): void
    {
        if ($instance->node->platform !== 'darwin') {
            $this->linux->removeInstance($instance);

            return;
        }

        $this->darwinCaddy->converge($instance->node);
        $this->darwinPhpFpm->converge($instance->node);
        $this->darwinCertificates->removeInstance($instance);
        $this->darwinSource->removeInstance($instance);
    }

    public function convergeWorkspace(Workspace $workspace): void
    {
        if ($workspace->instance->node->platform !== 'darwin') {
            $this->linux->convergeWorkspace($workspace);

            return;
        }

        $this->darwinSource->convergeWorkspace($workspace);
        $this->darwinPhpFpm->converge($workspace->instance->node);
        $this->darwinCertificates->convergeWorkspace($workspace);
        $this->darwinCaddy->converge($workspace->instance->node);
    }

    public function removeWorkspace(Workspace $workspace): void
    {
        if ($workspace->instance->node->platform !== 'darwin') {
            $this->linux->removeWorkspace($workspace);

            return;
        }

        $this->darwinCaddy->converge($workspace->instance->node);
        $this->darwinPhpFpm->converge($workspace->instance->node);
        $this->darwinCertificates->removeWorkspace($workspace);
        $this->darwinSource->removeWorkspace($workspace);
    }
}
