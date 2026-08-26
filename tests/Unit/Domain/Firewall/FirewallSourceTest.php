<?php

declare(strict_types=1);

use App\Domain\Firewall\FirewallSource;

it('normalizes wildcard hosts and CIDR networks', function (string $source, string $normalized): void {
    expect(FirewallSource::normalize($source))->toBe($normalized);
})->with([
    'wildcard' => ['any', 'any'],
    'IPv4 host CIDR' => ['192.0.2.12/32', '192.0.2.12'],
    'IPv4 network' => ['192.0.2.129/24', '192.0.2.0/24'],
    'IPv6 host CIDR' => ['2001:db8::1/128', '2001:db8::1'],
    'IPv6 network' => ['2001:db8:1::99/64', '2001:db8:1::/64'],
]);

it('rejects invalid addresses and CIDR prefixes', function (string $source): void {
    expect(fn (): string => FirewallSource::normalize($source))
        ->toThrow(InvalidArgumentException::class);
})->with([
    'blank' => [''],
    'missing address' => ['/24'],
    'whitespace' => [' 192.0.2.1'],
    'hostname' => ['example.test'],
    'IPv4 prefix too large' => ['192.0.2.1/33'],
    'IPv6 prefix too large' => ['2001:db8::1/129'],
    'invalid IPv4 octet' => ['192.0.2.999/24'],
]);
