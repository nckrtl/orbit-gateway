<?php

declare(strict_types=1);

namespace App\Infrastructure\AppDev;

use App\Domain\Shared\LifecycleStatus;
use App\Models\Instance;
use App\Models\Node;
use App\Models\Workspace;
use Illuminate\Support\Collection;

final readonly class AppDevSiteRepository
{
    /** @return Collection<int, AppDevSite> */
    public function forNode(Node $node): Collection
    {
        return $this->all()->where('nodeId', $node->id)->values();
    }

    /** @return Collection<int, AppDevSite> */
    public function all(): Collection
    {
        $instances = Instance::query()
            ->with(['node', 'workspaces'])
            ->whereIn('status', [LifecycleStatus::Provisioning->value, LifecycleStatus::Active->value])
            ->latest('id')
            ->get();
        $sites = collect();

        foreach ($instances as $instance) {
            if (! is_string($instance->node->wireguard_address)) {
                continue;
            }

            $sites->push($this->instanceSite($instance));

            foreach ($instance->workspaces as $workspace) {
                if (! in_array(
                    needle: $workspace->status,
                    haystack: [LifecycleStatus::Provisioning, LifecycleStatus::Active],
                    strict: true,
                )) {
                    continue;
                }

                $sites->push($this->workspaceSite($instance, $workspace));
            }
        }

        /** @var Collection<int, AppDevSite> $sites */
        return $sites->values();
    }

    private function instanceSite(Instance $instance): AppDevSite
    {
        return new AppDevSite(
            nodeId: $instance->node_id,
            nodeAddress: $instance->node->wireguard_address ?? '',
            scope: "instance-{$instance->id}",
            checkoutPath: $instance->checkout_path,
            documentRoot: $instance->document_root,
            phpVersion: $instance->php_version,
            hostname: $instance->hostname,
        );
    }

    private function workspaceSite(Instance $instance, Workspace $workspace): AppDevSite
    {
        return new AppDevSite(
            nodeId: $instance->node_id,
            nodeAddress: $instance->node->wireguard_address ?? '',
            scope: "workspace-{$workspace->id}",
            checkoutPath: $workspace->checkout_path,
            documentRoot: $instance->document_root,
            phpVersion: $workspace->php_version ?? $instance->php_version,
            hostname: $workspace->hostname,
        );
    }
}
