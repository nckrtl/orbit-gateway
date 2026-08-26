<?php

declare(strict_types=1);

use App\Domain\Firewall\FirewallPort;

it('normalizes one port and an ordered bounded range', function (string $port, string $normalized): void {
    expect(FirewallPort::normalize($port))->toBe($normalized);
})->with([
    'one port' => ['0443', '443'],
    'range' => ['08000:08010', '8000:8010'],
]);

it('rejects unsafe ports and ranges', function (string $port): void {
    expect(fn (): string => FirewallPort::normalize($port))
        ->toThrow(InvalidArgumentException::class);
})->with([
    'zero' => ['0'],
    'above maximum' => ['65536'],
    'reversed range' => ['9000:8000'],
    'missing range end' => ['8000:'],
    'comma list' => ['80,443'],
    'shell input' => ['443;id'],
]);
