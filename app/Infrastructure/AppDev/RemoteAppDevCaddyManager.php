<?php

declare(strict_types=1);

namespace App\Infrastructure\AppDev;

use App\Domain\AppDev\AppDevCaddyManager;
use App\Models\Node;

final readonly class RemoteAppDevCaddyManager implements AppDevCaddyManager
{
    public function __construct(
        private AppDevSiteRepository $sites,
        private AppDevCaddyConfigRenderer $renderer,
        private AppDevSshExecutor $ssh,
        private AppDevCaddyPublisher $publisher = new AppDevCaddyPublisher,
    ) {}

    public function converge(Node $node): void
    {
        $configuration = $this->renderer->render($this->sites->forNode($node));
        $version = bin2hex(random_bytes(8));
        $this->ssh->execute(
            $node,
            $this->publisher->command($configuration, $version),
            step: 'caddy-config',
            errorCode: 'app-dev.caddy_config_failed',
        );
    }
}
