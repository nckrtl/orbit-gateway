<?php

declare(strict_types=1);

use App\Infrastructure\WireGuard\WireGuardPeerAddressResolver;
use Illuminate\Http\Request;

describe(WireGuardPeerAddressResolver::class, function (): void {
    it('uses a valid non-loopback remote address directly', function (): void {
        $request = Request::create('/api/v1/nodes', server: ['REMOTE_ADDR' => '10.44.0.2']);

        expect(new WireGuardPeerAddressResolver()->resolve($request))->toBe('10.44.0.2');
    });

    it('uses the FastCGI peer value only behind the exact trusted loopback boundary', function (): void {
        $request = Request::create('/api/v1/nodes', server: [
            'REMOTE_ADDR' => '127.0.0.1',
            'ORBIT_TRUSTED_LOCAL_PROXY' => '1',
            'ORBIT_PEER_ADDRESS' => '10.44.0.3',
        ]);

        expect(new WireGuardPeerAddressResolver()->resolve($request))->toBe('10.44.0.3');
    });

    it('ignores FastCGI variables when the direct remote address is non-loopback', function (): void {
        $request = Request::create('/api/v1/nodes', server: [
            'REMOTE_ADDR' => '10.44.0.2',
            'ORBIT_TRUSTED_LOCAL_PROXY' => '1',
            'ORBIT_PEER_ADDRESS' => '10.44.0.3',
        ]);

        expect(new WireGuardPeerAddressResolver()->resolve($request))->toBe('10.44.0.2');
    });

    it('fails closed for spoofed or malformed address sources', function (array $server): void {
        $request = Request::create('/api/v1/nodes', server: $server);
        $request->headers->set('X-Orbit-Peer-Address', '10.44.0.9');
        $request->headers->set('X-Forwarded-For', '10.44.0.9');

        expect(new WireGuardPeerAddressResolver()->resolve($request))->toBeNull();
    })->with([
        'untrusted marker' => [[
            'REMOTE_ADDR' => '127.0.0.1',
            'ORBIT_TRUSTED_LOCAL_PROXY' => 'true',
            'ORBIT_PEER_ADDRESS' => '10.44.0.3',
        ]],
        'address with port' => [['REMOTE_ADDR' => '10.44.0.2:51820']],
        'address list' => [['REMOTE_ADDR' => '10.44.0.2, 10.44.0.3']],
        'address whitespace' => [['REMOTE_ADDR' => ' 10.44.0.2']],
        'loopback direct' => [['REMOTE_ADDR' => '::1']],
        'header only' => [['REMOTE_ADDR' => 'invalid']],
    ]);
});
