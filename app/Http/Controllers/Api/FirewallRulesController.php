<?php

declare(strict_types=1);

namespace App\Http\Controllers\Api;

use App\Actions\Firewall\ListFirewallRulesAction;
use App\Actions\Firewall\RemoveFirewallRuleAction;
use App\Actions\Firewall\StoreFirewallRuleAction;
use App\Data\Firewall\FirewallRuleData;
use App\Domain\Firewall\FirewallBackendStatus;
use App\Http\Controllers\Controller;
use App\Http\Requests\Firewall\StoreFirewallRuleRequest;
use App\Models\FirewallRule;
use App\Models\Node;
use Illuminate\Database\Eloquent\ModelNotFoundException;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

final class FirewallRulesController extends Controller
{
    public function index(
        Request $request,
        Node $node,
        ListFirewallRulesAction $action,
    ): JsonResponse {
        return response()->json([
            'data' => $action
                ->execute($node)
                ->map(static function (FirewallRule $rule): array {
                    $data = FirewallRuleData::fromModel($rule)->toArray();
                    unset($data['backend_status']);

                    return $data;
                })
                ->all(),
            'meta' => $this->meta($request),
        ]);
    }

    public function store(
        StoreFirewallRuleRequest $request,
        Node $node,
        StoreFirewallRuleAction $action,
    ): JsonResponse {
        $result = $action->execute($node, $request->getData());

        return response()->json(
            [
                'data' => FirewallRuleData::fromModel(
                    $result['rule'],
                    $result['backend_status'],
                )->toArray(),
                'meta' => $this->meta($request),
            ],
            $result['created'] ? 201 : 200,
        );
    }

    public function destroy(
        Request $request,
        Node $node,
        FirewallRule $firewallRule,
        RemoveFirewallRuleAction $action,
    ): JsonResponse {
        if ($firewallRule->node_id !== $node->id) {
            throw new ModelNotFoundException()->setModel(FirewallRule::class, [$firewallRule->name]);
        }

        $data = FirewallRuleData::fromModel($firewallRule, FirewallBackendStatus::Absent);
        $backendStatus = $action->execute($firewallRule);

        if ($backendStatus === FirewallBackendStatus::Inactive) {
            $data = FirewallRuleData::fromModel($firewallRule->refresh(), $backendStatus);
        }

        return response()->json([
            'data' => $data->toArray(),
            'meta' => $this->meta($request),
        ]);
    }

    /** @return array{request_id: string} */
    private function meta(Request $request): array
    {
        return ['request_id' => $request->attributes->getString('orbit.request_id')];
    }
}
