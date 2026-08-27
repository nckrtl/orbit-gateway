<?php

declare(strict_types=1);

it('keeps the Blade view directory in fresh deployments', function (): void {
    expect(resource_path('views/.gitkeep'))->toBeFile();
});
