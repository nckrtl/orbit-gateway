<?php

declare(strict_types=1);

use App\Domain\Nodes\NodeAccessAuthorizer;
use App\Domain\Nodes\RoleName;
use App\Domain\Shared\LifecycleStatus;
use App\Models\Node;

describe(NodeAccessAuthorizer::class, function (): void {
    it('allows an active Gateway node to access a peer without an access row', function (): void {
        $gateway = node_access_authorizer_node('gateway', RoleName::Gateway);
        $peer = node_access_authorizer_node('peer');
        $authorizer = app(NodeAccessAuthorizer::class);

        expect($authorizer->isGatewayNode($gateway))
            ->toBeTrue()
            ->and($authorizer->hasGatewayAuthority($gateway))
            ->toBeTrue()
            ->and($authorizer->allows($gateway, $peer))
            ->toBeTrue()
            ->and($gateway->accessibleNodes()->exists())
            ->toBeFalse()
            ->and($authorizer->hasAnyAccess($gateway))
            ->toBeTrue();
    });

    it('grants fleet authority through direct access to an active Gateway node', function (): void {
        $consumer = node_access_authorizer_node('consumer');
        $gateway = node_access_authorizer_node('gateway', RoleName::Gateway);
        $peer = node_access_authorizer_node('peer');
        node_access_authorizer_grant($consumer, $gateway);
        $authorizer = app(NodeAccessAuthorizer::class);

        expect($authorizer->hasGatewayAuthority($consumer))
            ->toBeTrue()
            ->and($authorizer->allows($consumer, $peer))
            ->toBeTrue()
            ->and($authorizer->hasAnyAccess($consumer))
            ->toBeTrue();
    });

    it('limits ordinary access to the exact directed edge', function (): void {
        $consumer = node_access_authorizer_node('consumer');
        $serving = node_access_authorizer_node('serving');
        $unrelated = node_access_authorizer_node('unrelated');
        node_access_authorizer_grant($consumer, $serving);
        $authorizer = app(NodeAccessAuthorizer::class);

        expect($authorizer->allows($consumer, $serving))
            ->toBeTrue()
            ->and($authorizer->allows($consumer, $unrelated))
            ->toBeFalse()
            ->and($authorizer->allows($serving, $consumer))
            ->toBeFalse()
            ->and($authorizer->hasGatewayAuthority($consumer))
            ->toBeFalse()
            ->and($authorizer->hasAnyAccess($consumer))
            ->toBeTrue();
    });

    it('allows an explicit self edge for a non-Gateway node', function (): void {
        $node = node_access_authorizer_node('self-serving');
        node_access_authorizer_grant($node, $node);

        expect(app(NodeAccessAuthorizer::class)->allows($node, $node))
            ->toBeTrue();
    });

    it('denies implicit self access for a non-Gateway node', function (): void {
        $node = node_access_authorizer_node('self-denied');

        expect(app(NodeAccessAuthorizer::class)->allows($node, $node))
            ->toBeFalse();
    });

    it('denies an active role-less node without an effective edge', function (): void {
        $consumer = node_access_authorizer_node('consumer');
        $serving = node_access_authorizer_node('serving');
        $authorizer = app(NodeAccessAuthorizer::class);

        expect($authorizer->isGatewayNode($consumer))
            ->toBeFalse()
            ->and($authorizer->hasGatewayAuthority($consumer))
            ->toBeFalse()
            ->and($authorizer->allows($consumer, $serving))
            ->toBeFalse()
            ->and($authorizer->accessibleNodeIds($consumer))
            ->toBeEmpty()
            ->and($authorizer->hasAnyAccess($consumer))
            ->toBeFalse();
    });

    it('does not grant implicit or fleet authority through an inactive Gateway role', function (): void {
        $inactiveGateway = node_access_authorizer_node(
            name: 'inactive-gateway',
            role: RoleName::Gateway,
            roleStatus: LifecycleStatus::Failed,
        );
        $consumer = node_access_authorizer_node('consumer');
        $peer = node_access_authorizer_node('peer');
        node_access_authorizer_grant($consumer, $inactiveGateway);
        $authorizer = app(NodeAccessAuthorizer::class);

        expect($authorizer->isGatewayNode($inactiveGateway))
            ->toBeFalse()
            ->and($authorizer->hasGatewayAuthority($inactiveGateway))
            ->toBeFalse()
            ->and($authorizer->allows($inactiveGateway, $peer))
            ->toBeFalse()
            ->and($authorizer->hasGatewayAuthority($consumer))
            ->toBeFalse()
            ->and($authorizer->allows($consumer, $inactiveGateway))
            ->toBeTrue()
            ->and($authorizer->allows($consumer, $peer))
            ->toBeFalse();
    });

    it('returns every node ID in stable order for fleet authority', function (): void {
        $consumer = node_access_authorizer_node('consumer');
        $firstPeer = node_access_authorizer_node('first-peer');
        $gateway = node_access_authorizer_node('gateway', RoleName::Gateway);
        $lastPeer = node_access_authorizer_node('last-peer');
        node_access_authorizer_grant($consumer, $gateway);

        $accessibleNodeIds = app(NodeAccessAuthorizer::class)->accessibleNodeIds($consumer);

        expect($accessibleNodeIds)->toBe([
            $consumer->id,
            $firstPeer->id,
            $gateway->id,
            $lastPeer->id,
        ]);
    });

    it('returns only direct node IDs in stable order without fleet authority', function (): void {
        $consumer = node_access_authorizer_node('consumer');
        $firstServing = node_access_authorizer_node('first-serving');
        $secondServing = node_access_authorizer_node('second-serving');
        node_access_authorizer_node('unrelated');
        node_access_authorizer_grant($consumer, $secondServing);
        node_access_authorizer_grant($consumer, $firstServing);

        $accessibleNodeIds = app(NodeAccessAuthorizer::class)->accessibleNodeIds($consumer);

        expect($accessibleNodeIds)->toBe([
            $firstServing->id,
            $secondServing->id,
        ]);
    });
});

function node_access_authorizer_node(
    string $name,
    ?RoleName $role = null,
    LifecycleStatus $roleStatus = LifecycleStatus::Active,
): Node {
    $node = Node::query()->create([
        'name' => $name,
        'status' => LifecycleStatus::Active,
        'public_ssh_host' => '192.0.2.10',
    ]);

    if ($role instanceof RoleName) {
        $node->roles()->create([
            'role' => $role,
            'status' => $roleStatus,
        ]);
    }

    return $node;
}

function node_access_authorizer_grant(Node $consumer, Node $serving): void
{
    $consumer->accessibleNodes()->attach($serving);
}
