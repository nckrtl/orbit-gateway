<?php

declare(strict_types=1);

namespace App\Http\Middleware;

use App\Domain\Nodes\NodeAccessAuthorizer;
use App\Http\Authorization\ActiveGatewayMissing;
use App\Http\Authorization\RequiresNodeAccess;
use App\Http\Authorization\ServingNode;
use App\Http\Authorization\ServingNodeResolver;
use App\Models\Node;
use Closure;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Route;
use ReflectionClass;
use ReflectionMethod;
use Symfony\Component\HttpFoundation\Response;

final readonly class RequireNodeAccess
{
    public function __construct(
        private NodeAccessAuthorizer $authorizer,
        private ServingNodeResolver $resolver,
    ) {}

    /**
     * @mago-expect lint:halstead The method keeps the fail-closed decision order explicit.
     * @mago-expect analysis:mixed-assignment The authenticated peer resolver returns a Node.
     * @param Closure(Request): Response $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        $scope = $this->scope($request);

        if (! $scope instanceof ServingNode) {
            $request->attributes->set('orbit.error_code', 'node_access.scope_missing');

            return $this->scopeMissing();
        }

        $consumer = $request->user();

        if (! $consumer instanceof Node) {
            $request->attributes->set('orbit.error_code', 'node_access.scope_missing');

            return $this->scopeMissing();
        }

        if ($scope === ServingNode::Collection) {
            if ($this->authorizer->hasAnyAccess($consumer)) {
                return $next($request);
            }

            $request->attributes->set('orbit.error_code', 'node_access.required');

            return $this->required($consumer, null);
        }

        try {
            $servingNodes = $this->resolver->resolve($request, $scope);
        } catch (ActiveGatewayMissing) {
            $request->attributes->set('orbit.error_code', 'node_access.required');

            return $this->required($consumer, null);
        }

        if ($servingNodes === []) {
            return $next($request);
        }

        foreach ($servingNodes as $servingNode) {
            if ($this->authorizer->allows($consumer, $servingNode)) {
                return $next($request);
            }
        }

        $request->attributes->set('orbit.error_code', 'node_access.required');

        return $this->required($consumer, $servingNodes[0]);
    }

    /**
     * @mago-expect analysis:impossible-condition The middleware also fails closed without a route.
     * @mago-expect analysis:mixed-assignment Laravel resolves controller actions dynamically.
     */
    private function scope(Request $request): ?ServingNode
    {
        $route = $request->route();

        if (! $route instanceof Route) {
            return null;
        }

        $controller = $route->getController();

        if (! is_object($controller)) {
            return null;
        }

        $method = new ReflectionMethod($controller, $route->getActionMethod());
        $methodAttribute = $method->getAttributes(RequiresNodeAccess::class)[0] ?? null;

        if ($methodAttribute !== null) {
            return $methodAttribute->newInstance()->servingNode;
        }

        $class = new ReflectionClass($controller);
        $classAttribute = $class->getAttributes(RequiresNodeAccess::class)[0] ?? null;

        return $classAttribute?->newInstance()->servingNode;
    }

    private function required(Node $consumer, ?Node $serving): JsonResponse
    {
        return response()->json([
            'error' => [
                'code' => 'node_access.required',
                'message' => 'Node access is required.',
                'details' => [
                    'consumer_node' => ['id' => $consumer->id, 'name' => $consumer->name],
                    'serving_node' => $serving instanceof Node
                        ? ['id' => $serving->id, 'name' => $serving->name]
                        : null,
                ],
            ],
        ], 403);
    }

    private function scopeMissing(): JsonResponse
    {
        return response()->json([
            'error' => [
                'code' => 'node_access.scope_missing',
                'message' => 'Node access scope is missing.',
                'details' => [],
            ],
        ], 500);
    }
}
