<?php

declare(strict_types=1);

it('uses ORBIT_HOME as the portable mutable data root', function (): void {
    expect(config('orbit.home'))->toBe('/tmp/orbit-gateway-testing');
});
