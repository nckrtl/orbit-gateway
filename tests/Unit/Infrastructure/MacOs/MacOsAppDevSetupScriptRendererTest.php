<?php

declare(strict_types=1);

use App\Data\Nodes\MacOsAppDevSetupFactsData;
use App\Domain\MacOs\MacOsAppDevSetupPlan;
use App\Domain\MacOs\MacOsLocalActionCommand;
use App\Domain\MacOs\MacOsProtectedCheck;
use App\Domain\MacOs\MacOsProtectedDriftException;
use App\Domain\Nodes\RoleName;
use App\Domain\Shared\LifecycleStatus;
use App\Infrastructure\MacOs\MacOsAppDevSetupScriptRenderer;
use App\Infrastructure\MacOs\MacOsAppDevSetupVerifier;
use App\Infrastructure\MacOs\MacOsProtectedStateInspector;
use App\Infrastructure\MacOs\MacOsSshConnectionFactory;
use App\Infrastructure\MacOs\MacOsSteadyStateCommandGuard;
use App\Infrastructure\Ssh\SshKeyProvider;
use App\Models\Node;
use App\Models\NodeRole;
use Symfony\Component\Process\Process;

it('provides the native macOS setup and verification seams', function (string $class): void {
    expect(class_exists($class))->toBeTrue();
})->with([
    'local action command' => [MacOsLocalActionCommand::class],
    'protected check' => [MacOsProtectedCheck::class],
    'protected drift exception' => [MacOsProtectedDriftException::class],
    'setup script renderer' => [MacOsAppDevSetupScriptRenderer::class],
    'setup verifier' => [MacOsAppDevSetupVerifier::class],
    'protected state inspector' => [MacOsProtectedStateInspector::class],
    'SSH connection factory' => [MacOsSshConnectionFactory::class],
    'steady-state command guard' => [MacOsSteadyStateCommandGuard::class],
]);

it('renders the complete ordered Apple Bash setup with bounded rollback', function (): void {
    $plan = macos_setup_renderer()->render(
        macos_setup_node(),
        macos_setup_assignment(),
        macos_setup_facts(),
    );

    expect($plan)
        ->toBeInstanceOf(MacOsAppDevSetupPlan::class)
        ->and($plan->summary)
        ->toContain(
            'Enable Remote Login',
            'Install the Orbit PF redirect',
            'Install the root dnsmasq service',
            'Install the local resolver',
        )
        ->and($plan->script)
        ->toStartWith("#!/bin/bash\n")
        ->toContain(
            "EXPECTED_PLATFORM='darwin'",
            "EXPECTED_ARCHITECTURE='arm64'",
            "EXPECTED_USERNAME='nckrtl'",
            "EXPECTED_HOME='/Users/nckrtl'",
            "WIREGUARD_ADDRESS='10.44.0.8'",
            "NODE_TLD='test'",
            "GATEWAY_WIREGUARD_ADDRESS='10.44.0.1'",
            'from="10.44.0.1",no-agent-forwarding,no-port-forwarding,no-X11-forwarding,no-pty,no-user-rc ssh-ed25519 AAAAC3NzaGatewayKey orbit-gateway',
            'https://raw.githubusercontent.com/Homebrew/install/b9990527570f7e07d5393f37447b8293ec0a78de/install.sh',
            '12479a24be3f5307eecac7cde670fad7118640f031229e964f544b1367b52a41',
            '/etc/pf.anchors/com.orbit.app-dev',
            '/Library/Application Support/Orbit/app-dev/dnsmasq.conf',
            '/Library/LaunchDaemons/com.orbit.dnsmasq.plist',
            '/etc/resolver/${NODE_TLD}',
            '${EXPECTED_HOME}/.ssh/authorized_keys',
            '${BREW_PREFIX}/opt/openssl@3/bin/openssl',
            'admin off',
            'recovery:homebrew-preserved',
            'recovery:remote-login-restored',
            'recovery:remote-login-restore-failed',
        )
        ->not->toContain('sudo -n')
        ->not->toContain('brew upgrade')
        ->not->toContain('brew services')
        ->not->toContain('flock')
        ->not->toContain('readlink -f')
        ->not->toContain('mv -T')
        ->not->toContain('cp --preserve')
        ->not->toContain('/etc/sudoers')
        ->not->toContain('/Users/orbit')
        ->not->toContain('wg0.conf');

    $stages = [
        'snapshot_remote_login',
        'install_homebrew',
        'enable_remote_login',
        'install_pf',
        'install_dnsmasq',
        'install_resolver',
        'install_user_state',
        'verify_local_state',
        'SETUP_SUCCEEDED=1',
    ];
    $positions = array_map(
        static fn (string $stage): int|false => strpos($plan->script, "\n{$stage}\n"),
        $stages,
    );

    expect($positions)
        ->not->toContain(false);

    $sorted = $positions;
    sort($sorted);

    expect($positions)->toBe($sorted);
});

it('keeps every sudo call inside the approved local setup and rollback categories', function (): void {
    $script = macos_setup_renderer()->render(
        macos_setup_node(),
        macos_setup_assignment(),
        macos_setup_facts(),
    )->script;
    $splitLines = preg_split('/\R/', $script);
    $sudoLines = array_values(array_filter(
        is_array($splitLines) ? $splitLines : [],
        static fn (string $line): bool => str_contains($line, '/usr/bin/sudo'),
    ));

    expect($sudoLines)
        ->not->toBeEmpty()->each(function ($line): void {
            $line->toMatch(
                '#(?:systemsetup|pfctl|com\.orbit\.dnsmasq|DNSMASQ_|PF_|RESOLVER_|source_path|destination_path|snapshot_name|/etc/resolver|/bin/launchctl)#',
            );
        })->and($script)->toContain(
            "trap 'cleanup $?' EXIT",
            "trap 'exit 130' INT",
            'PROTECTED_SNAPSHOTS_READY=1',
            'AUTHORIZED_KEYS_SNAPSHOTTED=1',
            'CADDY_SNAPSHOTTED=1',
        )
        ->not->toContain('command=')
        ->not->toContain('ssh ')
        ->not->toContain('IdentityFile');
});

it('restores every protected file and prior loaded state after a later activation failure', function (): void {
    $script = macos_setup_renderer()->render(
        macos_setup_node(),
        macos_setup_assignment(),
        macos_setup_facts(),
    )->script;

    foreach ([
        ['pf-anchor',      '${PF_ANCHOR}'],
        ['pf-config',      '${PF_CONFIG}'],
        ['dnsmasq-config', '${DNSMASQ_CONFIG}'],
        ['dnsmasq-plist',  '${DNSMASQ_PLIST}'],
        ['resolver',       '${RESOLVER_PATH}'],
    ] as [$snapshot, $path]) {
        expect($script)
            ->toContain("snapshot_root_file '{$snapshot}' \"{$path}\"")
            ->toContain("restore_root_file '{$snapshot}' \"{$path}\"");
    }

    expect($script)
        ->toContain(
            'if [ "${DNSMASQ_WAS_LOADED}" -eq 1 ]',
            'if [ "${PF_WAS_ENABLED}" -eq 1 ]',
            'if [ "${REMOTE_LOGIN_CHANGED}" -eq 1 ] && [ "${REMOTE_LOGIN_WAS_ENABLED}" -eq 0 ]',
            'restore_user_file \'authorized-keys\'',
            'restore_user_file \'caddy-plist\'',
            'recovery:php-definition-restore-failed',
        );
});

it('classifies launchctl absence exactly and rejects unknown probes before mutation', function (): void {
    $script = macos_setup_renderer()->render(
        macos_setup_node(),
        macos_setup_assignment(),
        macos_setup_facts(),
    )->script;

    expect($script)
        ->toContain(
            'launchctl_native_absence()',
            'launchctl_recognized_state()',
            'setup:launchctl-state-unavailable',
            'recovery:caddy-state-restore-failed',
            'recovery:php-state-restore-failed',
            'recovery:dnsmasq-state-restore-failed',
            'recovery:pf-state-restore-failed',
        );

    foreach ([
        '/bin/launchctl print system/com.orbit.dnsmasq >/dev/null 2>&1 && DNSMASQ_WAS_LOADED=1 || true',
        '/bin/launchctl print "gui/${USER_ID}/com.orbit.caddy" >/dev/null 2>&1 && CADDY_WAS_LOADED=1 || true',
        '/sbin/pfctl -e >/dev/null 2>&1 || true',
        '/sbin/pfctl -d >/dev/null 2>&1 || true',
    ] as $forbidden) {
        expect($script)->not->toContain($forbidden);
    }

    expect(substr_count(
        haystack: $script,
        needle: '/bin/launchctl bootout system/com.orbit.dnsmasq >/dev/null 2>&1 || true',
    ))->toBe(1);

    $functionStart = strpos(haystack: $script, needle: 'launchctl_recognized_state() {');
    expect($functionStart)->toBeInt();
    $functionEnd = strpos(haystack: $script, needle: "\n}", offset: $functionStart);
    expect($functionEnd)->toBeInt();
    $function = substr($script, $functionStart, $functionEnd - $functionStart + strlen("\n}"));
    foreach ([
        "state = running\nstate = stopped\n",
        "state = running\nstate = confused\n",
    ] as $stateOutput) {
        $process = new Process([
            '/bin/bash',
            '-c',
            $function."\n".'launchctl_recognized_state "$1"',
            'orbit-launchctl-state-test',
            $stateOutput,
        ]);

        expect($process->run())->not->toBe(0);
    }
});

it('parses as a portable noninteractive Bash script', function (): void {
    $script = macos_setup_renderer()->render(
        macos_setup_node(),
        macos_setup_assignment(),
        macos_setup_facts(),
    )->script;
    $process = new Process(['/bin/bash', '-n']);
    $process->setInput($script);

    $exitCode = $process->run();

    expect($exitCode)
        ->toBe(0)
        ->and($process->getErrorOutput())
        ->toBeEmpty();
});

it('selects only the supported Homebrew prefix for the registered architecture', function (
    string $architecture,
    string $prefix,
): void {
    $node = macos_setup_node();
    $node->architecture = $architecture;
    $facts = macos_setup_facts();
    $facts->architecture = $architecture;

    $script = macos_setup_renderer()->render($node, macos_setup_assignment(), $facts)->script;

    expect($script)->toContain("EXPECTED_BREW_PREFIX='{$prefix}'");
})->with([
    'Apple Silicon' => ['arm64', '/opt/homebrew'],
    'Intel' => ['x86_64', '/usr/local'],
]);

it('rejects an unsupported architecture before rendering setup commands', function (): void {
    $node = macos_setup_node();
    $node->architecture = 'powerpc';
    $facts = macos_setup_facts();
    $facts->architecture = 'powerpc';

    expect(fn (): MacOsAppDevSetupPlan => macos_setup_renderer()->render(
        $node,
        macos_setup_assignment(),
        $facts,
    ))
        ->toThrow(
            UnexpectedValueException::class,
            'The macOS architecture is not supported.',
        );
});

it('exposes only enum-backed protected drift details', function (): void {
    $drift = new MacOsProtectedDriftException(
        MacOsProtectedCheck::RootCaTrust,
        MacOsLocalActionCommand::GatewayTrust,
    );

    expect($drift->errorCode)
        ->toBe('macos.local_action_required')
        ->and($drift->status)
        ->toBe(409)
        ->and($drift->safeDetails)
        ->toBe([
            'check' => 'root-ca-trust',
            'local_command' => 'orbit gateway:trust',
        ]);
});

function macos_setup_renderer(): MacOsAppDevSetupScriptRenderer
{
    $keys = new class implements SshKeyProvider {
        public function privateKeyPath(): string
        {
            return '/gateway/id_ed25519';
        }

        public function publicKey(): string
        {
            return 'ssh-ed25519 AAAAC3NzaGatewayKey orbit-gateway';
        }
    };

    return new MacOsAppDevSetupScriptRenderer(
        sshKeys: $keys,
        gatewayAddressResolver: static fn (): string => '10.44.0.1',
    );
}

function macos_setup_node(): Node
{
    return new Node([
        'name' => 'mini',
        'status' => LifecycleStatus::Provisioning,
        'platform' => 'darwin',
        'architecture' => 'arm64',
        'tld' => 'test',
        'public_ssh_host' => '10.44.0.8',
        'ssh_user' => 'nckrtl',
        'wireguard_address' => '10.44.0.8',
    ]);
}

function macos_setup_assignment(): NodeRole
{
    return new NodeRole([
        'role' => RoleName::AppDev,
        'status' => LifecycleStatus::Provisioning,
    ]);
}

function macos_setup_facts(): MacOsAppDevSetupFactsData
{
    return new MacOsAppDevSetupFactsData(
        platform: 'darwin',
        architecture: 'arm64',
        username: 'nckrtl',
        homeDirectory: '/Users/nckrtl',
    );
}
