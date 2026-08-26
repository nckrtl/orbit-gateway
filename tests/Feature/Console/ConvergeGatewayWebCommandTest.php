<?php

declare(strict_types=1);

use App\Actions\Gateway\ConvergeGatewayWebAction;
use App\Domain\Gateway\GatewayWebConverger;
use App\Domain\Nodes\RoleName;
use App\Domain\Shared\LifecycleStatus;
use App\Domain\Shared\ResourceOperationException;
use App\Domain\WireGuard\VpnSettings;
use App\Models\Node;

describe('orbit:gateway-web:converge', function (): void {
    it('converges from the singleton typed Gateway state without arguments', function (): void {
        $web = new class implements GatewayWebConverger {
            /** @var list<array{string, string}> */
            public array $calls = [];

            public function converge(string $hostname, string $wireguardAddress): void
            {
                $this->calls[] = [$hostname, $wireguardAddress];
            }
        };
        app()->instance(GatewayWebConverger::class, $web);
        app(VpnSettings::class)->configure(subnet: '10.44.0.0/24', domain: 'private.test');
        $gateway = Node::query()->create([
            'name' => 'gateway',
            'status' => LifecycleStatus::Active,
            'platform' => 'linux',
            'architecture' => 'x86_64',
            'public_ssh_host' => '192.0.2.2',
            'wireguard_address' => '10.44.0.1',
        ]);
        $gateway
            ->roles()
            ->create([
                'role' => RoleName::Gateway,
                'status' => LifecycleStatus::Active,
            ]);

        $this
            ->artisan('orbit:gateway-web:converge')
            ->expectsOutput('Gateway web configuration converged.')
            ->assertSuccessful();

        expect($web->calls)->toBe([['gateway.private.test', '10.44.0.1']]);
    });

    it('fails before convergence when stored singleton state is incomplete or ambiguous', function (string $case): void {
        $web = new class implements GatewayWebConverger {
            public int $calls = 0;

            public function converge(string $hostname, string $wireguardAddress): void
            {
                $this->calls++;
            }
        };
        app()->instance(GatewayWebConverger::class, $web);

        if ($case !== 'missing-domain') {
            app(VpnSettings::class)->configure(subnet: '10.44.0.0/24', domain: 'private.test');
        }

        if ($case !== 'zero-gateways') {
            $gateway = gateway_web_state_node('gateway', $case === 'missing-address' ? null : '10.44.0.1');
            $gateway->roles()->create(['role' => RoleName::Gateway, 'status' => LifecycleStatus::Active]);
        }

        if ($case === 'multiple-gateways') {
            $second = gateway_web_state_node(name: 'other-gateway', wireguardAddress: '10.44.0.9');
            $second->roles()->create(['role' => RoleName::Gateway, 'status' => LifecycleStatus::Active]);
        }

        expect(fn (): mixed => app(ConvergeGatewayWebAction::class)->execute())
            ->toThrow(function (ResourceOperationException $exception): void {
                expect($exception->errorCode)
                    ->toBe('gateway.web_state_invalid')
                    ->and($exception->status)
                    ->toBe(409);
            });

        expect($web->calls)->toBe(0);
    })->with([
        'missing domain' => ['missing-domain'],
        'zero Gateway nodes' => ['zero-gateways'],
        'multiple Gateway nodes' => ['multiple-gateways'],
        'missing WireGuard address' => ['missing-address'],
    ]);
});

function gateway_web_state_node(string $name, ?string $wireguardAddress): Node
{
    return Node::query()->create([
        'name' => $name,
        'status' => LifecycleStatus::Active,
        'platform' => 'linux',
        'architecture' => 'x86_64',
        'public_ssh_host' => '192.0.2.2',
        'wireguard_address' => $wireguardAddress,
    ]);
}
