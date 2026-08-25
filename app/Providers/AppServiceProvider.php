<?php

declare(strict_types=1);

namespace App\Providers;

use App\Actions\Gateway\BootstrapGatewayAction;
use App\Actions\Nodes\AssignRoleAction;
use App\Domain\Nodes\NodeConverger;
use App\Domain\Settings\SettingRepository;
use App\Infrastructure\Files\ProtectedFileWriter;
use App\Infrastructure\Nodes\NativeNodeConverger;
use App\Infrastructure\Processes\NativeProcessRunner;
use App\Infrastructure\Processes\ProcessRunner;
use App\Infrastructure\Ssh\GatewaySshKeys;
use App\Infrastructure\Ssh\HostKeyScanner;
use App\Infrastructure\Ssh\KnownHostsRepository;
use App\Infrastructure\Ssh\KnownHostsStore;
use App\Infrastructure\Ssh\NativeSshExecutor;
use App\Infrastructure\Ssh\SshExecutor;
use App\Infrastructure\Ssh\SshHostKeyScanner;
use App\Infrastructure\Ssh\SshKeyProvider;
use App\Infrastructure\WireGuard\NativeWireGuardPeerConverger;
use App\Infrastructure\WireGuard\VpnConfigurationRepository;
use App\Infrastructure\WireGuard\WireGuardPeerConverger;
use App\Infrastructure\WireGuard\WireGuardServerConfigRenderer;
use Illuminate\Support\ServiceProvider;

final class AppServiceProvider extends ServiceProvider
{
    /** @var array<class-string, class-string> */
    public array $bindings = [
        HostKeyScanner::class => SshHostKeyScanner::class,
        NodeConverger::class => NativeNodeConverger::class,
        ProcessRunner::class => NativeProcessRunner::class,
        SshExecutor::class => NativeSshExecutor::class,
    ];

    public function register(): void
    {
        $this->app->singleton(
            BootstrapGatewayAction::class,
            static fn (): BootstrapGatewayAction => new BootstrapGatewayAction(
                assignRole: app(AssignRoleAction::class),
                settings: app(SettingRepository::class),
                processes: app(ProcessRunner::class),
                files: app(ProtectedFileWriter::class),
                orbitHome: rtrim(string: (string) config('orbit.home'), characters: '/'),
            ),
        );
        $this->app->singleton(
            KnownHostsRepository::class,
            static fn (): KnownHostsRepository => new KnownHostsRepository(
                rtrim(string: (string) config('orbit.home'), characters: '/').'/ssh/known_hosts',
            ),
        );
        $this->app->alias(KnownHostsRepository::class, KnownHostsStore::class);
        $this->app->singleton(
            GatewaySshKeys::class,
            static fn (): GatewaySshKeys => new GatewaySshKeys(
                rtrim(string: (string) config('orbit.home'), characters: '/').'/ssh/id_ed25519',
            ),
        );
        $this->app->alias(GatewaySshKeys::class, SshKeyProvider::class);
        $this->app->singleton(
            VpnConfigurationRepository::class,
            static fn (): VpnConfigurationRepository => new VpnConfigurationRepository(
                app(SettingRepository::class),
                rtrim(string: (string) config('orbit.home'), characters: '/'),
            ),
        );
        $this->app->singleton(
            NativeWireGuardPeerConverger::class,
            static fn (): NativeWireGuardPeerConverger => new NativeWireGuardPeerConverger(
                configuration: app(VpnConfigurationRepository::class),
                serverRenderer: app(WireGuardServerConfigRenderer::class),
                files: app(ProtectedFileWriter::class),
                processes: app(ProcessRunner::class),
                ssh: app(SshExecutor::class),
                orbitHome: rtrim(string: (string) config('orbit.home'), characters: '/'),
            ),
        );
        $this->app->alias(NativeWireGuardPeerConverger::class, WireGuardPeerConverger::class);
    }
}
