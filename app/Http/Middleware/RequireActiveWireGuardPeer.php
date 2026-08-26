<?php

declare(strict_types=1);

namespace App\Http\Middleware;

use App\Domain\Shared\LifecycleStatus;
use App\Models\Node;
use Closure;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

final class RequireActiveWireGuardPeer
{
    /** @param Closure(Request): Response $next */
    public function handle(Request $request, Closure $next): Response
    {
        $remoteAddress = $request->server('REMOTE_ADDR');

        if (! is_string($remoteAddress) || filter_var($remoteAddress, FILTER_VALIDATE_IP) === false) {
            $request->attributes->set('orbit.error_code', 'peer.identity_unknown');

            return $this->forbidden();
        }

        $node = Node::query()
            ->where('wireguard_address', $remoteAddress)
            ->where('status', LifecycleStatus::Active->value)
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
                'message' => 'Active WireGuard peer identity required.',
                'details' => [],
            ],
        ], 403);
    }
}
