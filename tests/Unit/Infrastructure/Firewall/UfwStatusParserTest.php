<?php

declare(strict_types=1);

use App\Infrastructure\Firewall\UfwRuleOwnership;
use App\Infrastructure\Firewall\UfwRuleShape;
use App\Infrastructure\Firewall\UfwStatusParser;
use App\Infrastructure\Firewall\UfwStoredRuleParser;

it('returns only rules with the exact managed comment', function (): void {
    $output = <<<'OUTPUT'
        Status: active

             To                         Action      From
             --                         ------      ----
        [ 1] 443/tcp                    ALLOW IN    Anywhere                   # orbit:node:7:firewall:web
        [ 2] 443/tcp (v6)               ALLOW IN    Anywhere (v6)              # orbit:node:7:firewall:web
        [ 3] 443/tcp                    ALLOW IN    192.0.2.0/24               # orbit:node:7:firewall:web-extra
        [ 4] 443/tcp                    ALLOW IN    198.51.100.0/24            # prefix-orbit:node:7:firewall:web
        [ 5] 443/tcp                    ALLOW IN    203.0.113.0/24             # unrelated
        OUTPUT;

    $rules = new UfwStatusParser()->ownedRules($output, 'orbit:node:7:firewall:web');

    expect($rules)
        ->toHaveCount(2)
        ->and(array_column($rules, 'family'))
        ->toBe(['v4', 'v6'])
        ->and(array_unique(array_column($rules, 'source')))
        ->toBe(['any']);
});

it('parses normalized named rule shapes without accepting unrelated same-port rules', function (): void {
    $output = <<<'OUTPUT'
        Status: active

             To                         Action      From
             --                         ------      ----
        [ 1] 8000:8010/udp              DENY IN     192.0.2.129/24            # orbit:node:7:firewall:admin
        [ 2] 8000:8010/udp              ALLOW IN    Anywhere                  # unrelated
        OUTPUT;

    expect(new UfwStatusParser()->ownedRules($output, 'orbit:node:7:firewall:admin'))
        ->toBe([[
            'action' => 'deny',
            'source' => '192.0.2.0/24',
            'port' => '8000:8010',
            'protocol' => 'udp',
            'family' => 'v4',
        ]]);
});

it('requires the exact managed destination and interface shape', function (): void {
    $output = <<<'OUTPUT'
        Status: active

             To                         Action      From
             --                         ------      ----
        [ 1] 10.44.0.2 80/tcp on orbit  ALLOW IN    Anywhere                   # orbit:app-dev-http
        OUTPUT;
    $expected = new UfwRuleShape(
        comment: 'orbit:app-dev-http',
        action: 'allow',
        direction: 'in',
        source: 'any',
        destination: '10.44.0.2',
        port: '80',
        protocol: 'tcp',
        inInterface: 'orbit',
        outInterface: null,
        family: 'v4',
    );

    expect(new UfwStatusParser()->ownership($output, $expected))->toBe(UfwRuleOwnership::Exact);
});

it('parses managed interface rules when a full target column leaves one action separator', function (): void {
    $output = <<<'OUTPUT'
        Status: active

             To                         Action      From
             --                         ------      ----
        [ 2] 10.44.0.3 80/tcp on orbit  ALLOW IN    Anywhere                   # orbit:app-dev-http
        [ 3] 10.44.0.3 443/tcp on orbit ALLOW IN    Anywhere                   # orbit:app-dev-https
        OUTPUT;

    $http = new UfwRuleShape(
        comment: 'orbit:app-dev-http',
        action: 'allow',
        direction: 'in',
        source: 'any',
        destination: '10.44.0.3',
        port: '80',
        protocol: 'tcp',
        inInterface: 'orbit',
        outInterface: null,
        family: 'v4',
    );
    $https = new UfwRuleShape(
        comment: 'orbit:app-dev-https',
        action: 'allow',
        direction: 'in',
        source: 'any',
        destination: '10.44.0.3',
        port: '443',
        protocol: 'tcp',
        inInterface: 'orbit',
        outInterface: null,
        family: 'v4',
    );
    $parser = new UfwStatusParser;

    expect($parser->ownership($output, $http))
        ->toBe(UfwRuleOwnership::Exact)
        ->and($parser->ownership($output, $https))
        ->toBe(UfwRuleOwnership::Exact);
});

it('requires the exact managed forwarding interfaces and endpoints', function (): void {
    $output = <<<'OUTPUT'
        Status: active

             To                         Action      From
             --                         ------      ----
        [ 1] 10.44.0.0/24 on orbit      ALLOW FWD   10.44.0.0/24 on orbit      # orbit:vpn-peer-forwarding
        OUTPUT;
    $expected = new UfwRuleShape(
        comment: 'orbit:vpn-peer-forwarding',
        action: 'allow',
        direction: 'fwd',
        source: '10.44.0.0/24',
        destination: '10.44.0.0/24',
        port: 'any',
        protocol: 'any',
        inInterface: 'orbit',
        outInterface: 'orbit',
        family: 'v4',
    );

    expect(new UfwStatusParser()->ownership($output, $expected))->toBe(UfwRuleOwnership::Exact);
});

it('reports same-comment broader and ambiguous shapes as drift', function (string $rules): void {
    $output = "Status: active\n\n{$rules}";
    $expected = new UfwRuleShape(
        comment: 'orbit:vpn-wireguard',
        action: 'allow',
        direction: 'in',
        source: 'any',
        destination: 'any',
        port: '51820',
        protocol: 'udp',
        inInterface: null,
        outInterface: null,
        family: null,
    );

    expect(new UfwStatusParser()->ownership($output, $expected))->toBe(UfwRuleOwnership::Drift);
})->with([
    'broader port range' => [
        '[ 1] 1:65535/udp                ALLOW IN    Anywhere                   # orbit:vpn-wireguard',
    ],
    'duplicate IPv4 ownership' => [
        "[ 1] 51820/udp                  ALLOW IN    Anywhere                   # orbit:vpn-wireguard\n"
            .'[ 2] 51820/udp                  ALLOW IN    Anywhere                   # orbit:vpn-wireguard',
    ],
    'unparseable managed line' => [
        '[ 1] OpenSSH                     ALLOW IN    Anywhere                   # orbit:vpn-wireguard',
    ],
    'unparseable compact managed line' => [
        '[ 1] OpenSSH ALLOW IN Anywhere # orbit:vpn-wireguard',
    ],
    'ambiguous action delimiter' => [
        '[ 1] 51820/udp ALLOW IN Anywhere ALLOW IN Anywhere # orbit:vpn-wireguard',
    ],
]);

it('does not infer ownership from an unrelated matching port', function (): void {
    $output = <<<'OUTPUT'
        Status: active

             To                         Action      From
             --                         ------      ----
        [ 1] 51820/udp                   ALLOW IN    Anywhere                   # operator-owned
        OUTPUT;
    $expected = new UfwRuleShape(
        comment: 'orbit:vpn-wireguard',
        action: 'allow',
        direction: 'in',
        source: 'any',
        destination: 'any',
        port: '51820',
        protocol: 'udp',
        inInterface: null,
        outInterface: null,
        family: null,
    );

    expect(new UfwStatusParser()->ownership($output, $expected))->toBe(UfwRuleOwnership::Missing);
});

it('requires every concrete family for family-neutral managed rules', function (): void {
    $expected = new UfwRuleShape(
        comment: 'orbit:public-ssh-recovery',
        action: 'allow',
        direction: 'in',
        source: 'any',
        destination: 'any',
        port: '22',
        protocol: 'tcp',
        inInterface: null,
        outInterface: null,
        family: null,
    );
    $ipv4 = '[ 1] 22/tcp                     ALLOW IN    Anywhere                   # orbit:public-ssh-recovery';
    $ipv6 = '[ 2] 22/tcp (v6)                ALLOW IN    Anywhere (v6)              # orbit:public-ssh-recovery';

    expect(new UfwStatusParser()->ownership("Status: active\n{$ipv4}\n", $expected))
        ->toBe(UfwRuleOwnership::Drift)
        ->and(new UfwStatusParser()->ownership("Status: active\n{$ipv4}\n{$ipv6}\n", $expected))
        ->toBe(UfwRuleOwnership::Exact);
});

it('parses exact protected UFW tuple ownership from both stored rule sources', function (): void {
    $expected = new UfwRuleShape(
        comment: 'orbit:public-ssh-recovery',
        action: 'allow',
        direction: 'in',
        source: 'any',
        destination: 'any',
        port: '22',
        protocol: 'tcp',
        inInterface: null,
        outInterface: null,
        family: null,
    );
    $comment = bin2hex('orbit:public-ssh-recovery');
    $stored = implode("\n", [
        "__orbit_ufw_tuple:v4:### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in comment={$comment}",
        "__orbit_ufw_tuple:v6:### tuple ### allow tcp 22 ::/0 any ::/0 in comment={$comment}",
    ]);

    expect(new UfwStoredRuleParser()->ownership($stored, $expected))->toBe(UfwRuleOwnership::Exact);
});

it('rejects stored managed tuples with a restricted public recovery shape', function (string $interface): void {
    $expected = new UfwRuleShape(
        comment: 'orbit:public-ssh-recovery',
        action: 'allow',
        direction: 'in',
        source: 'any',
        destination: 'any',
        port: '22',
        protocol: 'tcp',
        inInterface: null,
        outInterface: null,
        family: null,
    );
    $comment = bin2hex('orbit:public-ssh-recovery');
    $stored = implode("\n", [
        "__orbit_ufw_tuple:v4:### tuple ### allow tcp 22 10.44.0.2 any 0.0.0.0/0 {$interface} comment={$comment}",
        "__orbit_ufw_tuple:v6:### tuple ### allow tcp 22 fd00::2 any ::/0 {$interface} comment={$comment}",
    ]);

    expect(new UfwStoredRuleParser()->ownership($stored, $expected))->toBe(UfwRuleOwnership::Drift);
})->with([
    'wrong interface' => 'in_orbit',
    'wrong outgoing interface' => 'in!out_orbit',
]);
