<?php

declare(strict_types=1);

use App\Domain\AppDev\AppDevCaddyManager;
use App\Domain\AppDev\AppDevCertificateManager;
use App\Domain\AppDev\AppDevPhpFpmManager;
use App\Domain\AppDev\AppDevRuntimeConverger;
use App\Domain\AppDev\AppDevSourceManager;
use App\Infrastructure\AppDev\PlatformAppDevRuntimeConverger;
use App\Models\Instance;
use App\Models\Node;
use App\Models\Workspace;

it('delegates Linux unchanged and converges Darwin in source PHP certificate Caddy order', function (): void {
    $calls = new ArrayObject;
    $linux = platform_runtime_fake($calls, prefix: 'linux');
    $source = new class($calls) implements AppDevSourceManager {
        public function __construct(
            private ArrayObject $calls,
        ) {}

        public function convergeInstance(Instance $instance): void
        {
            $this->calls[] = 'darwin:source:instance';
        }

        public function removeInstance(Instance $instance): void
        {
            $this->calls[] = 'darwin:source-remove:instance';
        }

        public function convergeWorkspace(Workspace $workspace): void
        {
            $this->calls[] = 'darwin:source:workspace';
        }

        public function removeWorkspace(Workspace $workspace): void
        {
            $this->calls[] = 'darwin:source-remove:workspace';
        }
    };
    $php = new class($calls) implements AppDevPhpFpmManager {
        public function __construct(
            private ArrayObject $calls,
        ) {}

        public function converge(Node $node): void
        {
            $this->calls[] = 'darwin:php';
        }
    };
    $certificates = new class($calls) implements AppDevCertificateManager {
        public function __construct(
            private ArrayObject $calls,
        ) {}

        public function convergeInstance(Instance $instance): void
        {
            $this->calls[] = 'darwin:certificate:instance';
        }

        public function removeInstance(Instance $instance): void
        {
            $this->calls[] = 'darwin:certificate-remove:instance';
        }

        public function convergeWorkspace(Workspace $workspace): void
        {
            $this->calls[] = 'darwin:certificate:workspace';
        }

        public function removeWorkspace(Workspace $workspace): void
        {
            $this->calls[] = 'darwin:certificate-remove:workspace';
        }
    };
    $caddy = new class($calls) implements AppDevCaddyManager {
        public function __construct(
            private ArrayObject $calls,
        ) {}

        public function converge(Node $node): void
        {
            $this->calls[] = 'darwin:caddy';
        }
    };
    $runtime = new PlatformAppDevRuntimeConverger($linux, $source, $php, $certificates, $caddy);
    $linuxNode = new Node(['platform' => 'linux']);
    $linuxInstance = new Instance;
    $linuxInstance->setRelation('node', $linuxNode);
    $darwinNode = new Node(['platform' => 'darwin']);
    $darwinInstance = new Instance;
    $darwinInstance->setRelation('node', $darwinNode);
    $darwinWorkspace = new Workspace;
    $darwinWorkspace->setRelation('instance', $darwinInstance);

    $runtime->convergeInstance($linuxInstance);
    $runtime->convergeInstance($darwinInstance);
    $runtime->convergeWorkspace($darwinWorkspace);
    $runtime->removeWorkspace($darwinWorkspace);
    $runtime->removeInstance($darwinInstance);

    expect($calls->getArrayCopy())->toBe([
        'linux:converge-instance',
        'darwin:source:instance',
        'darwin:php',
        'darwin:certificate:instance',
        'darwin:caddy',
        'darwin:source:workspace',
        'darwin:php',
        'darwin:certificate:workspace',
        'darwin:caddy',
        'darwin:caddy',
        'darwin:php',
        'darwin:certificate-remove:workspace',
        'darwin:source-remove:workspace',
        'darwin:caddy',
        'darwin:php',
        'darwin:certificate-remove:instance',
        'darwin:source-remove:instance',
    ]);
});

function platform_runtime_fake(ArrayObject $calls, string $prefix): AppDevRuntimeConverger
{
    return new class($calls, $prefix) implements AppDevRuntimeConverger {
        public function __construct(
            private ArrayObject $calls,
            private string $prefix,
        ) {}

        public function convergeInstance(Instance $instance): void
        {
            $this->calls[] = "{$this->prefix}:converge-instance";
        }

        public function removeInstance(Instance $instance): void
        {
            $this->calls[] = "{$this->prefix}:remove-instance";
        }

        public function convergeWorkspace(Workspace $workspace): void
        {
            $this->calls[] = "{$this->prefix}:converge-workspace";
        }

        public function removeWorkspace(Workspace $workspace): void
        {
            $this->calls[] = "{$this->prefix}:remove-workspace";
        }
    };
}
