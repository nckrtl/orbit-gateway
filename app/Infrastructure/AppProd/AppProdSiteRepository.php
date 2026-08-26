<?php

declare(strict_types=1);

namespace App\Infrastructure\AppProd;

use App\Domain\Instances\CertificateMode;
use App\Domain\Shared\LifecycleStatus;
use App\Models\Instance;
use App\Models\Node;
use Illuminate\Support\Collection;

final readonly class AppProdSiteRepository
{
    /** @return Collection<int, AppProdSite> */
    public function forNode(Node $node): Collection
    {
        return Instance::query()
            ->with('app')
            ->where('node_id', $node->id)
            ->where('certificate_mode', CertificateMode::Acme->value)
            ->whereIn('status', [LifecycleStatus::Provisioning->value, LifecycleStatus::Active->value])
            ->orderBy('id')
            ->get()
            ->map(static fn (Instance $instance): AppProdSite => new AppProdSite(
                nodeId: $instance->node_id,
                appSlug: $instance->app->slug,
                instanceName: $instance->name,
                checkoutPath: $instance->checkout_path,
                documentRoot: $instance->document_root,
                phpVersion: $instance->php_version,
                hostname: $instance->hostname,
                instanceId: $instance->id,
            ));
    }
}
