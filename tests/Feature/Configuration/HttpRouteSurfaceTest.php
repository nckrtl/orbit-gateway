<?php

declare(strict_types=1);

use App\Providers\GatewayBoostServiceProvider;
use Illuminate\Support\Facades\File;
use Illuminate\Support\ServiceProvider;
use Symfony\Component\Process\Process;

/** @return list<array{methods: list<string>, uri: string, name: ?string}> */
$bootHttpRoutes = static function (string $environment, string $debug): array {
    $script = <<<'PHP'
        require 'vendor/autoload.php';
        $app = require 'bootstrap/app.php';
        $kernel = $app->make(Illuminate\Contracts\Http\Kernel::class);
        $kernel->bootstrap();
        $routes = [];

        foreach ($app->make('router')->getRoutes() as $route) {
            $routes[] = [
                'methods' => $route->methods(),
                'uri' => $route->uri(),
                'name' => $route->getName(),
            ];
        }

        echo json_encode($routes, JSON_THROW_ON_ERROR);
        PHP;
    $process = new Process(
        command: [PHP_BINARY, '-r', $script],
        cwd: base_path(),
        env: [
            'APP_ENV' => $environment,
            'APP_DEBUG' => $debug,
            'APP_RUNNING_IN_CONSOLE' => 'false',
        ],
    );
    $process->mustRun();
    $routes = json_decode($process->getOutput(), associative: true, flags: JSON_THROW_ON_ERROR);

    if (! is_array($routes)) {
        throw new RuntimeException('The HTTP route probe did not return a route list.');
    }

    /** @var list<array{methods: list<string>, uri: string, name: ?string}> $routes */
    return $routes;
};

it('disables framework file serving and owns Boost provider discovery', function (): void {
    /** @var array<string, mixed> $filesystems */
    $filesystems = require base_path('config/filesystems.php');
    /** @var array<string, mixed> $composer */
    $composer = json_decode(File::get(base_path('composer.json')), associative: true, flags: JSON_THROW_ON_ERROR);
    /** @var list<class-string> $providers */
    $providers = require base_path('bootstrap/providers.php');

    expect(data_get(target: $filesystems, key: 'disks.local.serve'))->toBeFalse();
    expect(data_get(target: $composer, key: 'extra.laravel.dont-discover'))
        ->toContain('laravel/boost');
    expect($providers)->toContain(GatewayBoostServiceProvider::class);
    expect(get_parent_class(GatewayBoostServiceProvider::class))->toBe(ServiceProvider::class);
});

it('exposes only API and health routes in an HTTP runtime', function (
    string $environment,
    string $debug,
) use ($bootHttpRoutes): void {
    $routes = $bootHttpRoutes($environment, $debug);

    foreach ($routes as $route) {
        expect($route['uri'] === 'up' || str_starts_with($route['uri'], 'api/v1/'))
            ->toBeTrue("Unexpected HTTP route [{$route['uri']}].");
    }

    expect(array_column($routes, 'uri'))->not->toContain('_boost/browser-logs', 'storage/{path}');
    expect(array_column($routes, 'name'))
        ->not
        ->toContain('boost.browser-logs', 'storage.local', 'storage.local.upload');
})->with([
    'local web runtime' => ['local', 'true'],
    'production web runtime' => ['production', 'false'],
]);

it('keeps Boost console commands available', function (): void {
    $process = new Process(
        command: [PHP_BINARY, 'artisan', 'list', '--raw'],
        cwd: base_path(),
        env: [
            'APP_ENV' => 'local',
            'APP_DEBUG' => 'true',
            'APP_RUNNING_IN_CONSOLE' => 'true',
        ],
    );
    $process->mustRun();

    expect($process->getOutput())
        ->toContain(
            'boost:add-skill',
            'boost:install',
            'boost:list-skills',
            'boost:mcp',
            'boost:update',
        );
});
