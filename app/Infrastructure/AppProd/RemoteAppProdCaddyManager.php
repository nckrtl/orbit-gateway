<?php

declare(strict_types=1);

namespace App\Infrastructure\AppProd;

use App\Domain\AppProd\AppProdCaddyManager;
use App\Models\Node;

final readonly class RemoteAppProdCaddyManager implements AppProdCaddyManager
{
    public function __construct(
        private AppProdSiteRepository $sites,
        private AppProdCaddyConfigRenderer $renderer,
        private AppProdSshExecutor $ssh,
        private AppProdCaddyPublisher $publisher = new AppProdCaddyPublisher,
    ) {}

    public function converge(Node $node): void
    {
        $configuration = $this->renderer->render($this->sites->forNode($node));
        $version = bin2hex(random_bytes(8));
        $this->ssh->execute(
            $node,
            $this->publisher->command($configuration, $version),
            step: 'app-prod-caddy-config',
            errorCode: 'app-prod.caddy_config_failed',
        );
    }
}
