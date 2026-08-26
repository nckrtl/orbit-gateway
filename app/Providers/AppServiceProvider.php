<?php

declare(strict_types=1);

namespace App\Providers;

use App\Actions\Gateway\BootstrapGatewayAction;
use App\Actions\Gateway\GatewayBootstrapIdentityValidator;
use App\Actions\Nodes\AssignRoleAction;
use App\Console\GatewayBoostInstallCommand;
use App\Domain\AppDev\AppDevRuntimeConverger;
use App\Domain\AppDev\AppDevSourceOperationLock;
use App\Domain\AppDev\PrivateDnsManager;
use App\Domain\AppProd\AppProdCaddyManager;
use App\Domain\AppProd\AppProdPhpFpmManager;
use App\Domain\AppProd\AppProdRuntimeConverger;
use App\Domain\AppProd\AppProdSourceManager;
use App\Domain\AppProd\AppProdUserManager;
use App\Domain\Certificates\GatewayCertificateIssuer;
use App\Domain\Certificates\LeafCertificateSigner;
use App\Domain\Firewall\FirewallManager;
use App\Domain\Gateway\GatewayVpnConverger;
use App\Domain\Gateway\GatewayWebConverger;
use App\Domain\MacOs\MacOsAppDevSetupRenderer;
use App\Domain\MacOs\MacOsAppDevVerifier;
use App\Domain\Nodes\NodeConverger;
use App\Domain\Nodes\NodeProjectionOperationLock;
use App\Domain\Processes\ProcessRuntimeManager;
use App\Domain\WireGuard\GatewayPeerProjectionManager;
use App\Domain\WireGuard\VpnSettings;
use App\Infrastructure\Activity\ActivityPropertiesObserver;
use App\Infrastructure\AppDev\DnsmasqPrivateDnsManager;
use App\Infrastructure\AppDev\NativeAppDevRuntimeConverger;
use App\Infrastructure\AppDev\NativeAppDevSourceOperationLock;
use App\Infrastructure\AppDev\PlatformAppDevRuntimeConverger;
use App\Infrastructure\AppDev\RemoteAppDevCaddyManager;
use App\Infrastructure\AppDev\RemoteAppDevCertificateManager;
use App\Infrastructure\AppDev\RemoteAppDevPhpFpmManager;
use App\Infrastructure\AppDev\RemoteAppDevSourceManager;
use App\Infrastructure\AppProd\NativeAppProdRuntimeConverger;
use App\Infrastructure\AppProd\RemoteAppProdCaddyManager;
use App\Infrastructure\AppProd\RemoteAppProdPhpFpmManager;
use App\Infrastructure\AppProd\RemoteAppProdSourceManager;
use App\Infrastructure\AppProd\RemoteAppProdUserManager;
use App\Infrastructure\Certificates\OpenSslGatewayCertificateIssuer;
use App\Infrastructure\Certificates\OpenSslGatewayCertificateValidator;
use App\Infrastructure\Certificates\OpenSslLeafCertificateSigner;
use App\Infrastructure\Files\NativeAtomicSymlinkPublisher;
use App\Infrastructure\Files\ProtectedFileWriter;
use App\Infrastructure\Firewall\NativeUfwFirewallManager;
use App\Infrastructure\Firewall\UfwStatusParser;
use App\Infrastructure\Gateway\GatewayCaddyConfigRenderer;
use App\Infrastructure\Gateway\GatewayCheckoutAccessConverger;
use App\Infrastructure\Gateway\GatewayFpmConfigRenderer;
use App\Infrastructure\Gateway\NativeGatewayCaddyConverger;
use App\Infrastructure\Gateway\NativeGatewayCertificatePublisher;
use App\Infrastructure\Gateway\NativeGatewayFpmConverger;
use App\Infrastructure\Gateway\NativeGatewayWebConverger;
use App\Infrastructure\MacOs\MacOsAppDevCaddyManager;
use App\Infrastructure\MacOs\MacOsAppDevCertificateManager;
use App\Infrastructure\MacOs\MacOsAppDevPhpFpmManager;
use App\Infrastructure\MacOs\MacOsAppDevSetupScriptRenderer;
use App\Infrastructure\MacOs\MacOsAppDevSetupVerifier as NativeMacOsAppDevSetupVerifier;
use App\Infrastructure\MacOs\MacOsAppDevSourceManager;
use App\Infrastructure\MacOs\MacOsLaunchdProcessRuntimeManager;
use App\Infrastructure\Nodes\NativeNodeConverger;
use App\Infrastructure\Nodes\NativeNodeProjectionOperationLock;
use App\Infrastructure\Nodes\NodeBootstrapCommandFactory;
use App\Infrastructure\Processes\CommandDeadline;
use App\Infrastructure\Processes\LaunchdProcessRenderer;
use App\Infrastructure\Processes\NativeProcessRunner;
use App\Infrastructure\Processes\PlatformProcessRuntimeManager;
use App\Infrastructure\Processes\ProcessRunner;
use App\Infrastructure\Processes\RemoteProcessRuntimeManager;
use App\Infrastructure\Ssh\GatewaySshKeys;
use App\Infrastructure\Ssh\HostKeyScanner;
use App\Infrastructure\Ssh\KnownHostsRepository;
use App\Infrastructure\Ssh\KnownHostsStore;
use App\Infrastructure\Ssh\NativeSshExecutor;
use App\Infrastructure\Ssh\SshExecutor;
use App\Infrastructure\Ssh\SshHostKeyScanner;
use App\Infrastructure\Ssh\SshKeyProvider;
use App\Infrastructure\WireGuard\NativeGatewayPeerProjectionManager;
use App\Infrastructure\WireGuard\NativeGatewayVpnConverger;
use App\Infrastructure\WireGuard\NativeWireGuardPeerConverger;
use App\Infrastructure\WireGuard\VpnConfigurationRepository;
use App\Infrastructure\WireGuard\WireGuardPeerConverger;
use App\Infrastructure\WireGuard\WireGuardServerConfigRenderer;
use App\Models\Activity;
use Illuminate\Support\ServiceProvider;
use Laravel\Boost\Console\InstallCommand;
use Laravel\Boost\Install\GuidelineComposer;

final class AppServiceProvider extends ServiceProvider
{
    /** @var array<class-string, class-string> */
    public array $bindings = [
        AppProdCaddyManager::class => RemoteAppProdCaddyManager::class,
        AppProdPhpFpmManager::class => RemoteAppProdPhpFpmManager::class,
        AppProdRuntimeConverger::class => NativeAppProdRuntimeConverger::class,
        AppProdSourceManager::class => RemoteAppProdSourceManager::class,
        AppProdUserManager::class => RemoteAppProdUserManager::class,
        FirewallManager::class => NativeUfwFirewallManager::class,
        HostKeyScanner::class => SshHostKeyScanner::class,
        MacOsAppDevSetupRenderer::class => MacOsAppDevSetupScriptRenderer::class,
        MacOsAppDevVerifier::class => NativeMacOsAppDevSetupVerifier::class,
        ProcessRunner::class => NativeProcessRunner::class,
        SshExecutor::class => NativeSshExecutor::class,
        PrivateDnsManager::class => DnsmasqPrivateDnsManager::class,
    ];

    public function register(): void
    {
        if (class_exists(GuidelineComposer::class)) {
            $this->app->singleton(GuidelineComposer::class, GatewayGuidelineComposer::class);
            $this->app->singleton(InstallCommand::class, GatewayBoostInstallCommand::class);
        }

        $this->app->singleton(CommandDeadline::class);
        $this->app->singleton(LaunchdProcessRenderer::class);
        $this->app->singleton(MacOsLaunchdProcessRuntimeManager::class);
        $this->app->singleton(
            ProcessRuntimeManager::class,
            static fn (): ProcessRuntimeManager => new PlatformProcessRuntimeManager(
                targets: app(\App\Domain\Processes\ProcessTargetResolver::class),
                linux: app(RemoteProcessRuntimeManager::class),
                darwin: app(MacOsLaunchdProcessRuntimeManager::class),
            ),
        );
        $this->app->singleton(
            NodeProjectionOperationLock::class,
            static fn (): NodeProjectionOperationLock => new NativeNodeProjectionOperationLock(
                rtrim(string: (string) config('orbit.home'), characters: '/').'/locks',
            ),
        );
        $this->app->singleton(
            AppDevSourceOperationLock::class,
            static fn (): AppDevSourceOperationLock => new NativeAppDevSourceOperationLock(
                rtrim(string: (string) config('orbit.home'), characters: '/').'/locks/app-dev-source',
            ),
        );
        $this->app->singleton(
            AppDevRuntimeConverger::class,
            static fn (): AppDevRuntimeConverger => new PlatformAppDevRuntimeConverger(
                linux: new NativeAppDevRuntimeConverger(
                    source: app(RemoteAppDevSourceManager::class),
                    phpFpm: app(RemoteAppDevPhpFpmManager::class),
                    certificates: app(RemoteAppDevCertificateManager::class),
                    caddy: app(RemoteAppDevCaddyManager::class),
                    dns: app(PrivateDnsManager::class),
                ),
                darwinSource: app(MacOsAppDevSourceManager::class),
                darwinPhpFpm: app(MacOsAppDevPhpFpmManager::class),
                darwinCertificates: app(MacOsAppDevCertificateManager::class),
                darwinCaddy: app(MacOsAppDevCaddyManager::class),
            ),
        );
        $this->app->singleton(
            NodeConverger::class,
            static fn (): NodeConverger => new NativeNodeConverger(
                hostKeys: app(HostKeyScanner::class),
                knownHosts: app(KnownHostsStore::class),
                sshKeys: app(SshKeyProvider::class),
                ssh: app(SshExecutor::class),
                bootstrapCommand: app(NodeBootstrapCommandFactory::class),
                wireGuard: app(WireGuardPeerConverger::class),
                appDevCaddy: app(RemoteAppDevCaddyManager::class),
            ),
        );
        $this->app->singleton(
            LeafCertificateSigner::class,
            static fn (): LeafCertificateSigner => new OpenSslLeafCertificateSigner(
                processes: app(ProcessRunner::class),
                orbitHome: rtrim(string: (string) config('orbit.home'), characters: '/'),
            ),
        );
        $this->app->singleton(
            GatewayCertificateIssuer::class,
            static fn (): GatewayCertificateIssuer => new OpenSslGatewayCertificateIssuer(
                processes: app(ProcessRunner::class),
                validator: app(OpenSslGatewayCertificateValidator::class),
                links: app(NativeAtomicSymlinkPublisher::class),
                orbitHome: rtrim(string: (string) config('orbit.home'), characters: '/'),
            ),
        );
        $this->app->singleton(
            GatewayVpnConverger::class,
            static fn (): GatewayVpnConverger => new NativeGatewayVpnConverger(
                renderer: app(WireGuardServerConfigRenderer::class),
                files: app(ProtectedFileWriter::class),
                processes: app(ProcessRunner::class),
                firewallParser: app(UfwStatusParser::class),
                orbitHome: rtrim(string: (string) config('orbit.home'), characters: '/'),
            ),
        );
        $this->app->singleton(
            GatewayWebConverger::class,
            static fn (): GatewayWebConverger => new NativeGatewayWebConverger(
                certificates: app(GatewayCertificateIssuer::class),
                caddyRenderer: app(GatewayCaddyConfigRenderer::class),
                fpmRenderer: app(GatewayFpmConfigRenderer::class),
                files: app(ProtectedFileWriter::class),
                checkout: new GatewayCheckoutAccessConverger(
                    processes: app(ProcessRunner::class),
                    checkoutPath: rtrim(string: (string) config('orbit.gateway_checkout'), characters: '/'),
                ),
                certificatePublisher: new NativeGatewayCertificatePublisher(
                    processes: app(ProcessRunner::class),
                    orbitHome: rtrim(string: (string) config('orbit.home'), characters: '/'),
                ),
                fpm: new NativeGatewayFpmConverger(app(ProcessRunner::class)),
                caddy: new NativeGatewayCaddyConverger(app(ProcessRunner::class)),
                orbitHome: rtrim(string: (string) config('orbit.home'), characters: '/'),
                checkoutPath: rtrim(string: (string) config('orbit.gateway_checkout'), characters: '/'),
            ),
        );
        $this->app->singleton(
            BootstrapGatewayAction::class,
            static fn (): BootstrapGatewayAction => new BootstrapGatewayAction(
                assignRole: app(AssignRoleAction::class),
                identity: app(GatewayBootstrapIdentityValidator::class),
                vpnSettings: app(VpnSettings::class),
                processes: app(ProcessRunner::class),
                files: app(ProtectedFileWriter::class),
                vpn: app(GatewayVpnConverger::class),
                web: app(GatewayWebConverger::class),
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
                app(VpnSettings::class),
                rtrim(string: (string) config('orbit.home'), characters: '/'),
            ),
        );
        $this->app->singleton(
            NativeGatewayPeerProjectionManager::class,
            static fn (): NativeGatewayPeerProjectionManager => new NativeGatewayPeerProjectionManager(
                configuration: app(VpnConfigurationRepository::class),
                serverRenderer: app(WireGuardServerConfigRenderer::class),
                files: app(ProtectedFileWriter::class),
                processes: app(ProcessRunner::class),
                orbitHome: rtrim(string: (string) config('orbit.home'), characters: '/'),
            ),
        );
        $this->app->alias(NativeGatewayPeerProjectionManager::class, GatewayPeerProjectionManager::class);
        $this->app->singleton(
            NativeWireGuardPeerConverger::class,
            static fn (): NativeWireGuardPeerConverger => new NativeWireGuardPeerConverger(
                configuration: app(VpnConfigurationRepository::class),
                gatewayPeers: app(GatewayPeerProjectionManager::class),
                ssh: app(SshExecutor::class),
            ),
        );
        $this->app->alias(NativeWireGuardPeerConverger::class, WireGuardPeerConverger::class);
    }

    public function boot(ActivityPropertiesObserver $activityPropertiesObserver): void
    {
        Activity::observe($activityPropertiesObserver);
    }
}
