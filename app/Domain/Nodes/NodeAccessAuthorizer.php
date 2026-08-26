<?php

declare(strict_types=1);

namespace App\Domain\Nodes;

use App\Domain\Shared\LifecycleStatus;
use App\Models\Node;

final readonly class NodeAccessAuthorizer
{
    public function allows(Node $consumer, Node $serving): bool
    {
        if ($this->isGatewayNode($consumer)) {
            return true;
        }

        if ($this->hasGatewayAuthority($consumer)) {
            return true;
        }

        return $consumer
            ->accessibleNodes()
            ->whereKey($serving->getKey())
            ->exists();
    }

    public function hasGatewayAuthority(Node $consumer): bool
    {
        if ($this->isGatewayNode($consumer)) {
            return true;
        }

        $gatewayId = $this->activeGatewayId();

        if ($gatewayId === null) {
            return false;
        }

        return $consumer
            ->accessibleNodes()
            ->whereKey($gatewayId)
            ->exists();
    }

    public function isGatewayNode(Node $node): bool
    {
        if ($node->status !== LifecycleStatus::Active) {
            return false;
        }

        return $node
            ->roles()
            ->where('role', RoleName::Gateway)
            ->where('status', LifecycleStatus::Active)
            ->exists();
    }

    public function hasAnyAccess(Node $consumer): bool
    {
        return (
            $this->isGatewayNode($consumer)
            || $this->hasGatewayAuthority($consumer)
            || $consumer->accessibleNodes()->exists()
        );
    }

    /** @return list<int> */
    public function accessibleNodeIds(Node $consumer): array
    {
        if ($this->isGatewayNode($consumer) || $this->hasGatewayAuthority($consumer)) {
            /** @var list<int> */
            return Node::query()
                ->orderBy('id')
                ->pluck('id')
                ->all();
        }

        /** @var list<int> */
        return $consumer
            ->accessibleNodes()
            ->orderBy('nodes.id')
            ->pluck('nodes.id')
            ->all();
    }

    private function activeGatewayId(): ?int
    {
        /** @var ?int */
        return Node::query()
            ->where('status', LifecycleStatus::Active)
            ->whereHas('roles', static function ($query): void {
                $query
                    ->where('role', RoleName::Gateway)
                    ->where('status', LifecycleStatus::Active);
            })
            ->orderBy('id')
            ->value('id');
    }
}
