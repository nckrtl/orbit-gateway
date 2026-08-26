<?php

declare(strict_types=1);

namespace App\Http\Middleware;

use App\Domain\Shared\LifecycleStatus;
use App\Infrastructure\WireGuard\WireGuardPeerAddressResolver;
use App\Models\Node;
use Closure;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

final readonly class RequireRegisteredWireGuardPeer
{
    public function __construct(
        private WireGuardPeerAddressResolver $addresses,
    ) {}

    /** @param Closure(Request): Response $next */
    public function handle(Request $request, Closure $next): Response
    {
        $address = $this->addresses->resolve($request);
        $node = $address === null
            ? null
            : Node::query()
                ->where('wireguard_address', $address)
                ->where('platform', 'darwin')
                ->whereIn('status', [
                    LifecycleStatus::Provisioning->value,
                    LifecycleStatus::Failed->value,
                    LifecycleStatus::Active->value,
                ])
                ->first();

        if (! $node instanceof Node) {
            $request->attributes->set('orbit.error_code', 'peer.identity_unknown');

            return $this->forbidden();
        }

        $request->setUserResolver(static fn (): Node => $node);

        return $next($request);
    }

    private function forbidden(): JsonResponse
    {
        return response()->json([
            'error' => [
                'code' => 'peer.identity_unknown',
                'message' => 'Registered Darwin WireGuard peer identity required.',
                'details' => [],
            ],
        ], 403);
    }
}
