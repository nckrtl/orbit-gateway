<?php

declare(strict_types=1);

use App\Domain\AppDev\AppDevSourceOperationLock;
use App\Domain\AppDev\RuntimeConvergenceException;
use App\Domain\Certificates\LeafCertificateSigner;
use App\Domain\Instances\CertificateMode;
use App\Domain\Shared\LifecycleStatus;
use App\Infrastructure\AppDev\AppDevCaddyConfigRenderer;
use App\Infrastructure\AppDev\AppDevCaddyPublisher;
use App\Infrastructure\AppDev\AppDevPhpFpmConfigRenderer;
use App\Infrastructure\AppDev\AppDevSiteRepository;
use App\Infrastructure\AppDev\AppDevSshExecutor;
use App\Infrastructure\AppDev\DnsmasqPrivateDnsManager;
use App\Infrastructure\AppDev\NativeAppDevSourceOperationLock;
use App\Infrastructure\AppDev\RemoteAppDevCaddyManager;
use App\Infrastructure\AppDev\RemoteAppDevCertificateManager;
use App\Infrastructure\AppDev\RemoteAppDevPhpFpmManager;
use App\Infrastructure\AppDev\RemoteAppDevSourceManager;
use App\Infrastructure\Processes\CommandResult;
use App\Infrastructure\Processes\NativeProcessRunner;
use App\Infrastructure\Processes\ProcessInvocation;
use App\Infrastructure\Ssh\HostKey;
use App\Infrastructure\Ssh\KnownHostsStore;
use App\Infrastructure\Ssh\RemoteCommand;
use App\Infrastructure\Ssh\SshKeyProvider;
use App\Models\App as OrbitApp;
use App\Models\Instance;
use App\Models\Node;
use App\Models\Workspace;
use Illuminate\Filesystem\Filesystem;
use Illuminate\Support\Str;
use Tests\Support\AppDevCaddyPublishHarness;
use Tests\Support\AppDevCaddyPublishScenario;
use Tests\Support\AppDevFakeProcessRunner;
use Tests\Support\AppDevFakeSshExecutor;

it('renders isolated pools and private Caddy listeners for every active scope', function (): void {
    [$node, $instance, $workspace] = app_dev_runtime_models();
    $sites = new AppDevSiteRepository()->forNode($node);
    $fpm = new AppDevPhpFpmConfigRenderer()->render($sites);
    $caddy = new AppDevCaddyConfigRenderer()->render($sites);
    $adapted = new NativeProcessRunner()->run(new ProcessInvocation(
        arguments: ['caddy', 'adapt', '--config', '-', '--adapter', 'caddyfile'],
        input: $caddy,
    ));

    expect($sites)
        ->toHaveCount(2)
        ->and($fpm)
        ->toContain(
            '[orbit-instance-1]',
            'listen = /run/php/orbit-instance-1.sock',
            '[orbit-workspace-1]',
            'listen = /run/php/orbit-workspace-1.sock',
            'listen.group = caddy',
        )
        ->and($caddy)
        ->toContain(
            "https://{$instance->hostname}",
            "https://{$workspace->hostname}",
            'bind 10.44.0.3',
            'php_fastcgi unix//run/php/orbit-instance-1.sock',
            'tls /etc/caddy/orbit-certificates/instance-1/current/cert.pem',
        )
        ->not->toContain('0.0.0.0', ':80')->and($adapted->succeeded())->toBeTrue()->and($adapted->stdout)->toContain(
            '10.44.0.3:443',
        )
        ->not->toContain('0.0.0.0:443', '127.0.0.1:443');
});

it('uses only generated instance paths and registered Git worktrees for source removal', function (): void {
    [, $instance, $workspace] = app_dev_runtime_models();
    [$manager, $ssh] = source_manager();

    $manager->convergeInstance($instance);
    $manager->convergeWorkspace($workspace);
    $manager->removeWorkspace($workspace);
    $manager->removeInstance($instance);

    expect($ssh->commands)
        ->toHaveCount(4)
        ->and($ssh->commands[0]->arguments)
        ->toContain('git@github.com:acme/site.git', '/home/orbit/apps/acme', 'public')
        ->and($ssh->commands[0]->input)
        ->toContain(
            'git -C "$checkout" remote get-url origin',
            'realpath -e "$existing_parent"',
            'test ! -L "$current"',
            'setfacl -P -R -m u:caddy:--- "$checkout_root"',
            'find -P "$checkout_root" -type d -exec setfacl -m d:u:caddy:--- -- {} +',
            'setfacl -m u:caddy:--x /home/orbit /home/orbit/apps "$checkout"',
            'setfacl -P -R -m u:caddy:r-X "$document_root_real"',
            'find -P "$document_root_real" -type d -exec setfacl -m d:u:caddy:r-x -- {} +',
        )
        ->not->toContain('sudo setfacl')->and($ssh->commands[1]->input)->toContain(
            'git -C "$checkout" symbolic-ref --quiet --short HEAD',
            'realpath -e "$existing_parent"',
            'test ! -L "$current"',
            'test ! -L "$checkout"',
            'case "$segment" in',
            "''|.|..|*[!A-Za-z0-9._-]*) return 1",
            'setfacl -P -R -m u:caddy:--- "$checkout_root"',
            'find -P "$checkout_root" -type d -exec setfacl -m d:u:caddy:--- -- {} +',
            'setfacl -m u:caddy:--x "$checkout"',
            'setfacl -P -R -m u:caddy:r-X "$document_root_real"',
            'find -P "$document_root_real" -type d -exec setfacl -m d:u:caddy:r-x -- {} +',
        )
        ->not->toContain('sudo setfacl')->and($ssh->commands[2]->input)->toContain(
            'worktree list --porcelain',
            'worktree remove --force -- "$checkout"',
        )->and($ssh->commands[3]->input)->toContain(
            'case "$(realpath -e "$parent")" in',
            'test ! -L "$checkout"',
            'git -C "$checkout" rev-parse --show-toplevel',
            'rm -rf -- "$checkout"',
        );
});

it('reconciles exact document-root ACLs and refuses symlink drift', function (): void {
    if (! is_executable('/usr/bin/setfacl') || posix_getpwnam('nobody') === false) {
        $this->markTestSkipped('The ACL behavior test requires setfacl and the nobody account.');
    }

    [, $instance] = app_dev_runtime_models();
    [$manager, $ssh] = source_manager();
    $manager->convergeInstance($instance);
    $command = $ssh->commands[0];
    $filesystem = new Filesystem;
    $root = sys_get_temp_dir().'/orbit-acl-'.Str::uuid();
    $checkout = "{$root}/apps/acme";

    try {
        $filesystem->makeDirectory("{$checkout}/public/build", mode: 0o700, recursive: true);
        $filesystem->makeDirectory("{$checkout}/storage/app/public", mode: 0o700, recursive: true);
        $filesystem->makeDirectory("{$checkout}/web", mode: 0o700, recursive: true);
        $filesystem->put("{$checkout}/.env", 'APP_KEY=secret');
        $filesystem->put("{$checkout}/storage/app/public/upload.txt", 'upload');
        symlink('../storage/app/public', "{$checkout}/public/storage");
        initialise_acl_test_repository($checkout, repository: 'git@github.com:acme/site.git');
        chmod(filename: $root, permissions: 0o711);
        chmod(filename: "{$root}/apps", permissions: 0o711);

        $first = run_app_dev_command_locally($command, $root);

        expect($first->succeeded())
            ->toBeTrue($first->stderr)
            ->and(acl_for("{$checkout}/public"))
            ->toContain('user:nobody:r-x', 'default:user:nobody:r-x')
            ->and(acl_for("{$checkout}/public/build"))
            ->toContain('user:nobody:r-x', 'default:user:nobody:r-x')
            ->and(acl_for("{$checkout}/.env"))
            ->toContain('user:nobody:---')
            ->and(acl_for("{$checkout}/storage/app/public"))
            ->toContain('user:nobody:r-x', 'default:user:nobody:r-x')
            ->and(acl_for("{$checkout}/storage/app/public/upload.txt"))
            ->toContain('user:nobody:r--');

        $filesystem->put("{$checkout}/public/build/manifest.json", '{}');

        expect(acl_for("{$checkout}/public/build/manifest.json"))
            ->toContain('user:nobody:r-x', '#effective:r--');

        $instance->document_root = 'web';
        $ssh->commands = [];
        $manager->convergeInstance($instance);
        $second = run_app_dev_command_locally($ssh->commands[0], $root);

        expect($second->succeeded())
            ->toBeTrue($second->stderr)
            ->and(access_acl_permissions_for(user: 'nobody', path: "{$checkout}/public"))
            ->toBe('---')
            ->and(acl_for("{$checkout}/public"))
            ->toContain('default:user:nobody:---')
            ->and(acl_for("{$checkout}/web"))
            ->toContain('user:nobody:r-x', 'default:user:nobody:r-x');

        $outside = "{$root}/outside";
        $filesystem->makeDirectory($outside, mode: 0o755, recursive: true);
        $filesystem->put("{$outside}/outside.txt", 'outside');
        chmod(filename: "{$outside}/outside.txt", permissions: 0o644);
        symlink($outside, "{$checkout}/public/outside");
        $instance->document_root = 'public';
        $ssh->commands = [];
        $manager->convergeInstance($instance);
        $externalLink = run_app_dev_command_locally($ssh->commands[0], $root);

        expect($externalLink->succeeded())
            ->toBeFalse()
            ->and(access_acl_permissions_for(user: 'nobody', path: "{$checkout}/public"))
            ->toBe('---')
            ->and(acl_for("{$checkout}/public"))
            ->toContain('default:user:nobody:---')
            ->and(acl_for("{$outside}/outside.txt"))
            ->not->toContain('user:nobody:');

        unlink("{$checkout}/public/outside");
        $external = "{$root}/external-repository";
        $filesystem->makeDirectory("{$external}/public", mode: 0o700, recursive: true);
        $filesystem->put("{$external}/outside.txt", 'outside');
        initialise_acl_test_repository($external, repository: 'git@github.com:acme/site.git');
        $filesystem->moveDirectory($checkout, "{$root}/retired-checkout");
        symlink($external, $checkout);

        $blocked = run_app_dev_command_locally($command, $root);

        expect($blocked->succeeded())
            ->toBeFalse()
            ->and(acl_for("{$external}/outside.txt"))
            ->not->toContain('user:nobody:');
    } finally {
        if (is_link($checkout)) {
            unlink($checkout);
        }

        $filesystem->deleteDirectory($root);
    }
});

it('rejects source links to private checkout files before granting Caddy access', function (): void {
    if (! is_executable('/usr/bin/setfacl') || posix_getpwnam('nobody') === false) {
        $this->markTestSkipped('The ACL behavior test requires setfacl and the nobody account.');
    }

    [, $instance] = app_dev_runtime_models();
    [$manager, $ssh] = source_manager();
    $manager->convergeInstance($instance);
    $command = $ssh->commands[0];
    $filesystem = new Filesystem;
    $root = sys_get_temp_dir().'/orbit-private-link-'.Str::uuid();
    $checkout = "{$root}/apps/acme";

    try {
        $filesystem->makeDirectory("{$checkout}/public", mode: 0o700, recursive: true);
        $filesystem->put("{$checkout}/.env", 'APP_KEY=secret');
        symlink('../.env', "{$checkout}/public/environment");
        initialise_acl_test_repository($checkout, repository: 'git@github.com:acme/site.git');
        chmod(filename: $root, permissions: 0o711);
        chmod(filename: "{$root}/apps", permissions: 0o711);

        $result = run_app_dev_command_locally($command, $root);

        expect($result->succeeded())
            ->toBeFalse()
            ->and(access_acl_permissions_for(user: 'nobody', path: "{$checkout}/public"))
            ->toBe('---')
            ->and(acl_for("{$checkout}/public"))
            ->toContain('default:user:nobody:---')
            ->and(acl_for("{$checkout}/.env"))
            ->toContain('user:nobody:---');
    } finally {
        $filesystem->deleteDirectory($root);
    }
});

it('revokes checkout access before rejecting a replaced document root', function (): void {
    if (! is_executable('/usr/bin/setfacl') || posix_getpwnam('nobody') === false) {
        $this->markTestSkipped('The ACL behavior test requires setfacl and the nobody account.');
    }

    [, $instance] = app_dev_runtime_models();
    [$manager, $ssh] = source_manager();
    $manager->convergeInstance($instance);
    $command = $ssh->commands[0];
    $filesystem = new Filesystem;
    $root = sys_get_temp_dir().'/orbit-document-root-link-'.Str::uuid();
    $checkout = "{$root}/apps/acme";
    $outside = "{$root}/outside";

    try {
        $filesystem->makeDirectory("{$checkout}/public", mode: 0o700, recursive: true);
        $filesystem->put("{$checkout}/public/index.php", '<?php');
        initialise_acl_test_repository($checkout, repository: 'git@github.com:acme/site.git');
        $filesystem->makeDirectory($outside, mode: 0o755, recursive: true);
        $filesystem->put("{$outside}/outside.txt", 'outside');
        chmod(filename: $root, permissions: 0o711);
        chmod(filename: "{$root}/apps", permissions: 0o711);

        $first = run_app_dev_command_locally($command, $root);
        expect($first->succeeded())
            ->toBeTrue($first->stderr)
            ->and(acl_for($checkout))
            ->toContain('user:nobody:--x');

        $filesystem->deleteDirectory("{$checkout}/public");
        symlink($outside, "{$checkout}/public");

        $replaced = run_app_dev_command_locally($command, $root);

        expect($replaced->succeeded())
            ->toBeFalse()
            ->and(access_acl_permissions_for(user: 'nobody', path: $checkout))
            ->toBe('---')
            ->and(acl_for($checkout))
            ->toContain('default:user:nobody:---')
            ->and(acl_for($outside))
            ->not->toContain('user:nobody:');
    } finally {
        $filesystem->deleteDirectory($root);
    }
});

it('rejects nested links inside Laravel public storage before granting Caddy access', function (): void {
    if (! is_executable('/usr/bin/setfacl') || posix_getpwnam('nobody') === false) {
        $this->markTestSkipped('The ACL behavior test requires setfacl and the nobody account.');
    }

    [, $instance] = app_dev_runtime_models();
    [$manager, $ssh] = source_manager();
    $manager->convergeInstance($instance);
    $command = $ssh->commands[0];
    $filesystem = new Filesystem;
    $root = sys_get_temp_dir().'/orbit-nested-link-'.Str::uuid();
    $checkout = "{$root}/apps/acme";
    $outside = "{$root}/outside";

    try {
        $filesystem->makeDirectory("{$checkout}/public", mode: 0o700, recursive: true);
        $filesystem->makeDirectory("{$checkout}/storage/app/public", mode: 0o700, recursive: true);
        $filesystem->makeDirectory($outside, mode: 0o755, recursive: true);
        $filesystem->put("{$outside}/outside.txt", 'outside');
        symlink('../storage/app/public', "{$checkout}/public/storage");
        symlink($outside, "{$checkout}/storage/app/public/outside");
        initialise_acl_test_repository($checkout, repository: 'git@github.com:acme/site.git');
        chmod(filename: $root, permissions: 0o711);
        chmod(filename: "{$root}/apps", permissions: 0o711);

        $result = run_app_dev_command_locally($command, $root);

        expect($result->succeeded())
            ->toBeFalse()
            ->and(access_acl_permissions_for(user: 'nobody', path: "{$checkout}/public"))
            ->toBe('---')
            ->and(acl_for("{$checkout}/public"))
            ->toContain('default:user:nobody:---')
            ->and(access_acl_permissions_for(user: 'nobody', path: "{$checkout}/storage/app/public"))
            ->toBe('---')
            ->and(acl_for("{$checkout}/storage/app/public"))
            ->toContain('default:user:nobody:---');
    } finally {
        $filesystem->deleteDirectory($root);
    }
});

it('grants and releases traversal for a private custom workspace parent', function (): void {
    if (
        ! is_executable('/usr/bin/setfacl')
        || ! is_executable('/usr/bin/setfattr')
        || posix_getpwnam('nobody') === false
    ) {
        $this->markTestSkipped('The ACL behavior test requires ACL, xattr, and the nobody account.');
    }

    [, $instance, $workspace] = app_dev_runtime_models();
    $workspace->checkout_path = '/home/orbit/projects/acme-feature';
    $workspace->save();
    [$manager, $ssh] = source_manager();
    $manager->convergeWorkspace($workspace);
    $command = $ssh->commands[0];
    $filesystem = new Filesystem;
    $root = sys_get_temp_dir().'/orbit-workspace-acl-'.Str::uuid();
    $instanceCheckout = "{$root}/apps/acme";
    $projects = "{$root}/projects";

    try {
        $filesystem->makeDirectory("{$instanceCheckout}/public", mode: 0o700, recursive: true);
        $filesystem->put("{$instanceCheckout}/public/index.php", '<?php');
        initialise_acl_test_repository($instanceCheckout, repository: 'git@github.com:acme/site.git');
        $filesystem->makeDirectory($projects, mode: 0o700, recursive: true);
        setfacl_for(user: 'nobody', permissions: 'r-x', path: $projects);
        setfacl_for(user: 'www-data', permissions: 'r-x', path: $projects);
        $mask = new NativeProcessRunner()->run(new ProcessInvocation([
            'setfacl',
            '-n',
            '-m',
            'm::--x',
            $projects,
        ]));
        expect($mask->succeeded())->toBeTrue($mask->stderr);
        $originalAcl = acl_for($projects);

        $converged = run_app_dev_command_locally($command, $root);
        $statePath = $filesystem->files("{$root}/.orbit/caddy-traversal-state")[0]->getPathname();
        $stateLines = explode("\n", $filesystem->get($statePath));
        $marker = xattr_for($projects);

        expect($converged->succeeded())
            ->toBeTrue($converged->stderr)
            ->and(acl_for($projects))
            ->toContain('user:nobody:--x', 'other::---')
            ->and(effective_access_acl_permissions_for(user: 'www-data', path: $projects))
            ->toBe('--x')
            ->and(acl_for("{$root}/projects/acme-feature/public"))
            ->toContain('user:nobody:r-x')
            ->and($marker)
            ->toMatch('/\A[0-9a-f]{64}\z/')
            ->and($stateLines[2] ?? null)
            ->toBe($marker);

        $ssh->commands = [];
        $manager->removeWorkspace($workspace);
        $removed = run_app_dev_command_locally($ssh->commands[0], $root);

        expect($removed->succeeded())
            ->toBeTrue($removed->stderr)
            ->and(acl_for($projects))
            ->toBe($originalAcl)
            ->and(xattr_for($projects))
            ->toBeNull();
    } finally {
        $filesystem->deleteDirectory($root);
    }
});

it('completes traversal cleanup after the ACL was restored before state removal', function (): void {
    if (
        ! is_executable('/usr/bin/setfacl')
        || ! is_executable('/usr/bin/setfattr')
        || posix_getpwnam('nobody') === false
    ) {
        $this->markTestSkipped('The ACL behavior test requires ACL, xattr, and the nobody account.');
    }

    [, , $workspace] = app_dev_runtime_models();
    $workspace->checkout_path = '/home/orbit/projects/acme-feature';
    $workspace->save();
    [$manager, $ssh] = source_manager();
    $manager->convergeWorkspace($workspace);
    $filesystem = new Filesystem;
    $root = sys_get_temp_dir().'/orbit-workspace-cleanup-recovery-'.Str::uuid();
    $instanceCheckout = "{$root}/apps/acme";
    $projects = "{$root}/projects";
    $stateDirectory = "{$root}/.orbit/caddy-traversal-state";

    try {
        $filesystem->makeDirectory("{$instanceCheckout}/public", mode: 0o700, recursive: true);
        $filesystem->put("{$instanceCheckout}/public/index.php", '<?php');
        initialise_acl_test_repository($instanceCheckout, repository: 'git@github.com:acme/site.git');
        $filesystem->makeDirectory($projects, mode: 0o700, recursive: true);
        $originalAcl = acl_for($projects);

        $converged = run_app_dev_command_locally($ssh->commands[0], $root);
        expect($converged->succeeded())->toBeTrue($converged->stderr);

        $statePath = $filesystem->files($stateDirectory)[0]->getPathname();
        $stateLines = explode("\n", $filesystem->get($statePath));
        $restore = new NativeProcessRunner()->run(new ProcessInvocation(
            arguments: ['setfacl', '--set-file=-', $projects],
            input: implode("\n", array_slice(array: $stateLines, offset: 3)),
        ));
        $removeMarker = new NativeProcessRunner()->run(new ProcessInvocation([
            'setfattr',
            '-x',
            'user.orbit.caddy_traversal',
            '--',
            $projects,
        ]));
        expect($restore->succeeded())
            ->toBeTrue($restore->stderr)
            ->and($removeMarker->succeeded())
            ->toBeTrue($removeMarker->stderr);

        $ssh->commands = [];
        $manager->removeWorkspace($workspace);
        $removed = run_app_dev_command_locally($ssh->commands[0], $root);

        expect($removed->succeeded())
            ->toBeTrue($removed->stderr)
            ->and(acl_for($projects))
            ->toBe($originalAcl)
            ->and($filesystem->files($stateDirectory))
            ->toBeEmpty();
    } finally {
        $filesystem->deleteDirectory($root);
    }
});

it('rejects replacement of a custom traversal directory without applying stale ACL state', function (): void {
    if (! is_executable('/usr/bin/setfacl') || posix_getpwnam('nobody') === false) {
        $this->markTestSkipped('The ACL behavior test requires setfacl and the nobody account.');
    }

    [, , $workspace] = app_dev_runtime_models();
    $workspace->checkout_path = '/home/orbit/projects/acme-feature';
    $workspace->save();
    [$manager, $ssh] = source_manager();
    $manager->convergeWorkspace($workspace);
    $command = $ssh->commands[0];
    $filesystem = new Filesystem;
    $root = sys_get_temp_dir().'/orbit-workspace-replacement-'.Str::uuid();
    $instanceCheckout = "{$root}/apps/acme";
    $projects = "{$root}/projects";

    try {
        $filesystem->makeDirectory("{$instanceCheckout}/public", mode: 0o700, recursive: true);
        $filesystem->put("{$instanceCheckout}/public/index.php", '<?php');
        initialise_acl_test_repository($instanceCheckout, repository: 'git@github.com:acme/site.git');
        $filesystem->makeDirectory($projects, mode: 0o700, recursive: true);

        $first = run_app_dev_command_locally($command, $root);
        expect($first->succeeded())
            ->toBeTrue(
                "exit={$first->exitCode}\nstdout={$first->stdout}\nstderr={$first->stderr}",
            );

        expect($filesystem->deleteDirectory($projects))
            ->toBeTrue()
            ->and(is_dir($projects))
            ->toBeFalse();
        $filesystem->makeDirectory($projects, mode: 0o700, recursive: true);
        $statePath = $filesystem->files("{$root}/.orbit/caddy-traversal-state")[0]->getPathname();
        $stateLines = explode("\n", $filesystem->get($statePath));
        $identity = stat($projects);
        expect($identity)->toBeArray();
        $stateLines[1] = "{$identity['dev']}:{$identity['ino']}";
        $filesystem->put($statePath, implode("\n", $stateLines));
        chmod(filename: $statePath, permissions: 0o600);

        $replacement = run_app_dev_command_locally($command, $root);

        expect($replacement->succeeded())
            ->toBeFalse()
            ->and(acl_for($projects))
            ->not->toContain('user:nobody:');

        setfacl_for(user: 'nobody', permissions: '--x', path: $projects);
        set_xattr(path: $projects, value: str_repeat(string: 'f', times: 64));
        $ssh->commands = [];
        $manager->removeWorkspace($workspace);
        $removal = run_app_dev_command_locally($ssh->commands[0], $root);

        expect($removal->succeeded())
            ->toBeFalse()
            ->and(access_acl_permissions_for(user: 'nobody', path: $projects))
            ->toBe('--x')
            ->and(xattr_for($projects))
            ->toBe(str_repeat(string: 'f', times: 64));
    } finally {
        $filesystem->deleteDirectory($root);
    }
});

it('recovers an orphan traversal marker before first convergence', function (): void {
    if (
        ! is_executable('/usr/bin/setfacl')
        || ! is_executable('/usr/bin/setfattr')
        || posix_getpwnam('nobody') === false
    ) {
        $this->markTestSkipped('The ACL behavior test requires ACL, xattr, and the nobody account.');
    }

    [, , $workspace] = app_dev_runtime_models();
    $workspace->checkout_path = '/home/orbit/projects/acme-feature';
    $workspace->save();
    [$manager, $ssh] = source_manager();
    $manager->convergeWorkspace($workspace);
    $filesystem = new Filesystem;
    $root = sys_get_temp_dir().'/orbit-workspace-orphan-marker-'.Str::uuid();
    $instanceCheckout = "{$root}/apps/acme";
    $projects = "{$root}/projects";
    $orphan = str_repeat(string: 'a', times: 64);

    try {
        $filesystem->makeDirectory("{$instanceCheckout}/public", mode: 0o700, recursive: true);
        $filesystem->put("{$instanceCheckout}/public/index.php", '<?php');
        initialise_acl_test_repository($instanceCheckout, repository: 'git@github.com:acme/site.git');
        $filesystem->makeDirectory($projects, mode: 0o700, recursive: true);
        set_xattr(path: $projects, value: $orphan);

        $converged = run_app_dev_command_locally($ssh->commands[0], $root);
        $statePath = $filesystem->files("{$root}/.orbit/caddy-traversal-state")[0]->getPathname();
        $stateLines = explode("\n", $filesystem->get($statePath));
        $marker = xattr_for($projects);

        expect($converged->succeeded())
            ->toBeTrue($converged->stderr)
            ->and($marker)
            ->toMatch('/\A[0-9a-f]{64}\z/')
            ->not
            ->toBe($orphan)
            ->and($stateLines[2] ?? null)
            ->toBe($marker);
    } finally {
        $filesystem->deleteDirectory($root);
    }
});

it('rejects a managed traversal marker when its state file is missing', function (): void {
    if (
        ! is_executable('/usr/bin/setfacl')
        || ! is_executable('/usr/bin/setfattr')
        || posix_getpwnam('nobody') === false
    ) {
        $this->markTestSkipped('The ACL behavior test requires ACL, xattr, and the nobody account.');
    }

    [, , $workspace] = app_dev_runtime_models();
    $workspace->checkout_path = '/home/orbit/projects/acme-feature';
    $workspace->save();
    [$manager, $ssh] = source_manager();
    $manager->convergeWorkspace($workspace);
    $command = $ssh->commands[0];
    $filesystem = new Filesystem;
    $root = sys_get_temp_dir().'/orbit-workspace-missing-state-'.Str::uuid();
    $instanceCheckout = "{$root}/apps/acme";
    $projects = "{$root}/projects";
    $stateDirectory = "{$root}/.orbit/caddy-traversal-state";

    try {
        $filesystem->makeDirectory("{$instanceCheckout}/public", mode: 0o700, recursive: true);
        $filesystem->put("{$instanceCheckout}/public/index.php", '<?php');
        initialise_acl_test_repository($instanceCheckout, repository: 'git@github.com:acme/site.git');
        $filesystem->makeDirectory($projects, mode: 0o700, recursive: true);

        $first = run_app_dev_command_locally($command, $root);
        expect($first->succeeded())->toBeTrue($first->stderr);
        $marker = xattr_for($projects);
        $statePath = $filesystem->files($stateDirectory)[0]->getPathname();
        expect($filesystem->delete($statePath))->toBeTrue();

        $drift = run_app_dev_command_locally($command, $root);

        expect($drift->succeeded())
            ->toBeFalse()
            ->and(xattr_for($projects))
            ->toBe($marker)
            ->and($filesystem->files($stateDirectory))
            ->toBeEmpty();
    } finally {
        $filesystem->deleteDirectory($root);
    }
});

it('retires saved traversal state when the original custom directory is gone', function (): void {
    if (! is_executable('/usr/bin/setfacl') || posix_getpwnam('nobody') === false) {
        $this->markTestSkipped('The ACL behavior test requires setfacl and the nobody account.');
    }

    [, , $workspace] = app_dev_runtime_models();
    $workspace->checkout_path = '/home/orbit/projects/acme-feature';
    $workspace->save();
    [$manager, $ssh] = source_manager();
    $manager->convergeWorkspace($workspace);
    $converge = $ssh->commands[0];
    $filesystem = new Filesystem;
    $root = sys_get_temp_dir().'/orbit-workspace-missing-parent-'.Str::uuid();
    $instanceCheckout = "{$root}/apps/acme";
    $projects = "{$root}/projects";
    $stateDirectory = "{$root}/.orbit/caddy-traversal-state";

    try {
        $filesystem->makeDirectory("{$instanceCheckout}/public", mode: 0o700, recursive: true);
        $filesystem->put("{$instanceCheckout}/public/index.php", '<?php');
        initialise_acl_test_repository($instanceCheckout, repository: 'git@github.com:acme/site.git');
        $filesystem->makeDirectory($projects, mode: 0o700, recursive: true);

        $first = run_app_dev_command_locally($converge, $root);
        expect($first->succeeded())->toBeTrue($first->stderr);
        expect($filesystem->files($stateDirectory))
            ->toHaveCount(1)
            ->and($filesystem->deleteDirectory($projects))
            ->toBeTrue();

        $ssh->commands = [];
        $manager->removeWorkspace($workspace);
        $removed = run_app_dev_command_locally($ssh->commands[0], $root);

        expect($removed->succeeded())->toBeTrue($removed->stderr);
        expect($filesystem->files($stateDirectory))->toBeEmpty();
    } finally {
        $filesystem->deleteDirectory($root);
    }
});

it('removes a never-converged workspace without requiring traversal state', function (string $checkoutPath): void {
    [, , $workspace] = app_dev_runtime_models();
    $workspace->checkout_path = $checkoutPath;
    $workspace->save();
    [$manager, $ssh] = source_manager();
    $manager->removeWorkspace($workspace);
    $filesystem = new Filesystem;
    $root = sys_get_temp_dir().'/orbit-workspace-never-converged-'.Str::uuid();
    $instanceCheckout = "{$root}/apps/acme";

    try {
        $filesystem->makeDirectory("{$instanceCheckout}/public", mode: 0o700, recursive: true);
        $filesystem->put("{$instanceCheckout}/public/index.php", '<?php');
        initialise_acl_test_repository($instanceCheckout, repository: 'git@github.com:acme/site.git');
        $localCheckoutPath = str_replace('/home/orbit', $root, $checkoutPath);
        $filesystem->makeDirectory(dirname($localCheckoutPath), mode: 0o700, recursive: true);

        $removed = run_app_dev_command_locally($ssh->commands[0], $root);

        expect($removed->succeeded())->toBeTrue($removed->stderr);
    } finally {
        $filesystem->deleteDirectory($root);
    }
})->with([
    'default path' => '/home/orbit/.orbit/worktrees/acme/feature',
    'custom path' => '/home/orbit/projects/acme-feature',
]);

it('removes an orphan traversal marker for a never-converged workspace', function (): void {
    if (! is_executable('/usr/bin/setfattr')) {
        $this->markTestSkipped('The traversal marker recovery test requires xattr tools.');
    }

    [, , $workspace] = app_dev_runtime_models();
    $workspace->checkout_path = '/home/orbit/projects/acme-feature';
    $workspace->save();
    [$manager, $ssh] = source_manager();
    $manager->removeWorkspace($workspace);
    $filesystem = new Filesystem;
    $root = sys_get_temp_dir().'/orbit-workspace-orphan-removal-'.Str::uuid();
    $instanceCheckout = "{$root}/apps/acme";
    $projects = "{$root}/projects";

    try {
        $filesystem->makeDirectory("{$instanceCheckout}/public", mode: 0o700, recursive: true);
        $filesystem->put("{$instanceCheckout}/public/index.php", '<?php');
        initialise_acl_test_repository($instanceCheckout, repository: 'git@github.com:acme/site.git');
        $filesystem->makeDirectory($projects, mode: 0o700, recursive: true);
        set_xattr(path: $projects, value: str_repeat(string: 'a', times: 64));

        $removed = run_app_dev_command_locally($ssh->commands[0], $root);

        expect($removed->succeeded())
            ->toBeTrue($removed->stderr)
            ->and(xattr_for($projects))
            ->toBeNull();
    } finally {
        $filesystem->deleteDirectory($root);
    }
});

it('rejects a corrupted workspace path before SSH or protected-path creation', function (): void {
    [, , $workspace] = app_dev_runtime_models();
    $workspace->checkout_path = '/home/orbit/custom/../.ssh/feature';
    [$manager, $ssh] = source_manager();

    expect(fn () => $manager->convergeWorkspace($workspace))
        ->toThrow(function (RuntimeConvergenceException $exception): void {
            expect($exception->errorCode)->toBe('workspace.checkout_path_unsafe');
        })
        ->and($ssh->commands)
        ->toBeEmpty();
});

it('releases a shared custom traversal ACL only after the last workspace is removed', function (): void {
    [, $instance, $first] = app_dev_runtime_models();
    $first->update(['checkout_path' => '/home/orbit/projects/first']);
    $second = Workspace::query()->create([
        'instance_id' => $instance->id,
        'name' => 'second',
        'branch' => 'second',
        'checkout_path' => '/home/orbit/projects/second',
        'hostname' => 'second.acme.app-dev.orbit',
        'status' => LifecycleStatus::Active,
    ]);
    [$manager, $ssh] = source_manager();

    $manager->removeWorkspace($first);

    expect($ssh->commands[0]->arguments)->not->toContain('/home/orbit/projects');

    $first->delete();
    $ssh->commands = [];
    $manager->removeWorkspace($second);

    expect($ssh->commands[0]->arguments)
        ->toContain('/home/orbit/projects');
});

it('computes shared traversal releases while the caller holds the per-node source lock', function (): void {
    [, $instance, $workspace] = app_dev_runtime_models();
    $workspace->update(['checkout_path' => '/home/orbit/projects/first']);
    $lock = new class($instance) implements AppDevSourceOperationLock {
        public bool $entered = false;

        public function __construct(
            private readonly Instance $instance,
        ) {}

        public function synchronized(int $nodeId, Closure $operation): mixed
        {
            $this->entered = true;
            Workspace::query()->create([
                'instance_id' => $this->instance->id,
                'name' => 'concurrent',
                'branch' => 'concurrent',
                'checkout_path' => '/home/orbit/projects/concurrent',
                'hostname' => 'concurrent.acme.app-dev.orbit',
                'status' => LifecycleStatus::Provisioning,
            ]);

            return $operation();
        }
    };
    [$manager, $ssh] = source_manager($lock);

    $lock->synchronized(
        $workspace->instance->node_id,
        fn (): mixed => $manager->removeWorkspace($workspace),
    );

    expect($lock->entered)
        ->toBeTrue()
        ->and($ssh->commands[0]->arguments)
        ->not->toContain('/home/orbit/projects');
});

it('stores per-node source locks outside mutable checkouts with private modes', function (): void {
    $filesystem = new Filesystem;
    $directory = sys_get_temp_dir().'/orbit-source-lock-'.Str::uuid();

    try {
        $result = new NativeAppDevSourceOperationLock($directory)->synchronized(
            nodeId: 42,
            operation: static fn (): string => 'locked',
        );

        expect($result)
            ->toBe('locked')
            ->and(fileperms($directory) & 0o777)
            ->toBe(0o700)
            ->and(fileperms("{$directory}/node-42.lock") & 0o777)
            ->toBe(0o600);
    } finally {
        $filesystem->deleteDirectory($directory);
    }
});

it('rejects a corrupted instance checkout path before SSH or recursive removal', function (): void {
    [, $instance] = app_dev_runtime_models();
    [$manager, $ssh] = source_manager();
    $instance->checkout_path = '/etc';

    expect(fn () => $manager->removeInstance($instance))
        ->toThrow(function (RuntimeConvergenceException $exception): void {
            expect($exception->errorCode)->toBe('instance.checkout_path_unsafe');
        })
        ->and($ssh->commands)
        ->toBeEmpty();
});

it('installs selected PHP versions and validates a complete staged FPM configuration before publication', function (): void {
    [$node] = app_dev_runtime_models(instancePhp: '8.4');
    $ssh = new AppDevFakeSshExecutor([
        new CommandResult(0, "8.5\n", '', 1, false),
    ]);
    $manager = new RemoteAppDevPhpFpmManager(
        sites: new AppDevSiteRepository,
        renderer: new AppDevPhpFpmConfigRenderer,
        ssh: app_dev_ssh($ssh),
    );

    $manager->converge($node);

    $publishCalls = collect($ssh->commands)
        ->filter(static fn (RemoteCommand $command): bool => str_contains($command->input ?? '', 'php-fpm.conf'))
        ->values();

    expect($ssh->commands)
        ->toHaveCount(4)
        ->and($ssh->commands[1]->input)
        ->toContain('apt-get install', '"php$version-fpm"')
        ->and($publishCalls)
        ->toHaveCount(2)
        ->and($publishCalls->first()?->input)
        ->toContain(
            'cp -- "$pool" "$temporary_directory/pool.d/"',
            'sudo "php-fpm$version" -y "$temporary_directory/php-fpm.conf" -t',
            'sudo mv -fT -- "$candidate" "$managed_configuration"',
        );
});

it('rejects an unsupported PHP version before target discovery or installation', function (): void {
    [$node] = app_dev_runtime_models(instancePhp: '9.9');
    $ssh = new AppDevFakeSshExecutor;
    $manager = new RemoteAppDevPhpFpmManager(
        sites: new AppDevSiteRepository,
        renderer: new AppDevPhpFpmConfigRenderer,
        ssh: app_dev_ssh($ssh),
    );

    expect(fn () => $manager->converge($node))
        ->toThrow(function (RuntimeConvergenceException $exception): void {
            expect($exception->errorCode)->toBe('app-dev.php_version_unsupported');
        })
        ->and($ssh->commands)
        ->toBeEmpty();
});

it('keeps leaf private keys on the target while publishing a gateway-signed certificate', function (): void {
    [, $instance] = app_dev_runtime_models();
    $ssh = new AppDevFakeSshExecutor([
        new CommandResult(0, 'CSR FROM TARGET', '', 1, false),
    ]);
    $signer = new class implements LeafCertificateSigner {
        /** @var list<array{hostname: string, csr: string}> */
        public array $calls = [];

        public function sign(string $hostname, string $certificateRequest): string
        {
            $this->calls[] = ['hostname' => $hostname, 'csr' => $certificateRequest];

            return "LEAF CERTIFICATE\n";
        }

        public function rootCertificate(): string
        {
            return "ROOT CERTIFICATE\n";
        }
    };
    $manager = new RemoteAppDevCertificateManager(app_dev_ssh($ssh), $signer);

    $manager->convergeInstance($instance);

    expect($ssh->commands)
        ->toHaveCount(2)
        ->and($ssh->commands[0]->input)
        ->toContain(
            'openssl genpkey -algorithm ED25519',
            'cat "$candidate/request.pem"',
            'openssl verify -CAfile "$current/root.pem" "$current/cert.pem"',
            'sha256sum "$current/root.pem"',
        )
        ->and($ssh->commands[0]->arguments)
        ->toContain(hash(algo: 'sha256', data: "ROOT CERTIFICATE\n"))
        ->and($signer->calls)
        ->toBe([['hostname' => 'acme.app-dev.orbit', 'csr' => 'CSR FROM TARGET']])
        ->and($ssh->commands[1]->input)
        ->toBe("LEAF CERTIFICATE\nROOT CERTIFICATE\n")
        ->and($ssh->commands[1]->arguments[2])
        ->toContain(
            'head -c "$certificate_length"',
            'openssl verify -CAfile',
            'sudo install -o root -g caddy -m 0640 -- "$published/key.pem"',
        )
        ->not->toContain('PRIVATE KEY');
});

it('publishes private Caddy and DNS configurations through complete preserved validation aggregates', function (): void {
    [$node] = app_dev_runtime_models();
    $ssh = new AppDevFakeSshExecutor;
    $caddyRenderer = new AppDevCaddyConfigRenderer;
    $caddy = new RemoteAppDevCaddyManager(
        sites: new AppDevSiteRepository,
        renderer: $caddyRenderer,
        ssh: app_dev_ssh($ssh),
    );
    $processes = new AppDevFakeProcessRunner;
    $dns = new DnsmasqPrivateDnsManager(new AppDevSiteRepository, $processes);

    $caddy->converge($node);
    $dns->converge();

    $expectedCaddy = $caddyRenderer->render(new AppDevSiteRepository()->forNode($node));

    expect($ssh->commands[0]->input)
        ->toContain(
            base64_encode($expectedCaddy),
            'source_main=$(readlink -f "$live_caddyfile")',
            'previous_fragments=$(dirname "$source_main")/fragments',
            'cp --preserve=mode,ownership -- "$fragment" "$candidate/fragments/"',
            'app-dev.caddy',
            "printf 'import %s/%s/fragments/*.caddy\n' \"\$versions\" \"\$version\"",
            'caddy validate --config "$published/Caddyfile"',
            'mv -fT -- "$candidate_link" "$live_caddyfile"',
        )
        ->and(array_slice(array: $ssh->commands[0]->arguments, offset: 0, length: 3))
        ->toBe(['sudo', 'bash', '-seu'])
        ->and($processes->invocations)
        ->toHaveCount(1)
        ->and($processes->invocations[0]->input)
        ->toContain(
            base64_encode(
                "# Managed by Orbit.\nhost-record=acme.app-dev.orbit,10.44.0.3\nhost-record=app-dev.orbit,10.44.0.3\nhost-record=feature.acme.app-dev.orbit,10.44.0.3\n",
            ),
            'cp -a -- /etc/dnsmasq.d/. "$validation/fragments/"',
            'sed "s#/etc/dnsmasq.d#$validation/fragments#g" /etc/dnsmasq.conf',
            'dnsmasq --test --conf-file="$validation/dnsmasq.conf"',
            'mv -fT -- "$candidate" "$managed"',
            'systemctl restart dnsmasq',
        );
});

it('retires only the exact package-default caddyfile while preserving modified config and orbit fragments', function (): void {
    $harness = new AppDevCaddyPublishHarness;

    try {
        $defaultResult = $harness->run(
            publisher: zero_site_publisher($harness),
            scenario: AppDevCaddyPublishScenario::packageDefault("package default\n", "package default\n"),
        );

        expect($defaultResult->exitCode)
            ->toBe(0)
            ->and($defaultResult->publishedFragments)
            ->toHaveKey('app-dev.caddy')
            ->not
            ->toHaveKey('unmanaged.caddy')
            ->and($defaultResult->liveMainAfter)
            ->toBe('import '.$harness->etcCaddyPath('orbit-versions/test-version/fragments/*.caddy')."\n");

        $orbitResult = $harness->run(
            publisher: zero_site_publisher($harness),
            scenario: AppDevCaddyPublishScenario::orbitAggregate("import fragments/*.caddy\n", [
                'custom.caddy' => "custom handler\n",
                'app-dev.caddy' => "stale app-dev\n",
            ]),
        );

        expect($orbitResult->exitCode)
            ->toBe(0)
            ->and($orbitResult->publishedFragments)
            ->toHaveKey('app-dev.caddy')
            ->toHaveKey('custom.caddy')
            ->not
            ->toHaveKey('unmanaged.caddy')
            ->and($orbitResult->publishedFragments['custom.caddy'])
            ->toBe("custom handler\n")
            ->and($orbitResult->publishedFragments['app-dev.caddy'])
            ->toBe("# Managed by Orbit.\n");

        $modifiedResult = $harness->run(
            publisher: zero_site_publisher($harness),
            scenario: AppDevCaddyPublishScenario::modifiedConfig("modified config\n", "package default\n"),
        );

        expect($modifiedResult->exitCode)
            ->toBe(0)
            ->and($modifiedResult->publishedFragments)
            ->toHaveKey('unmanaged.caddy')
            ->and($modifiedResult->publishedFragments['unmanaged.caddy'])
            ->toBe("modified config\n");
    } finally {
        $harness->cleanup();
    }
});

it('leaves the live caddy aggregate unchanged when staged validation fails during zero-site publication', function (): void {
    $harness = new AppDevCaddyPublishHarness;

    try {
        $result = $harness->run(
            publisher: zero_site_publisher($harness),
            scenario: AppDevCaddyPublishScenario::modifiedConfigWithValidationFailure(
                "modified config\n",
                "package default\n",
            ),
        );

        expect($result->exitCode)
            ->not
            ->toBe(0)
            ->and($result->liveMainAfter)
            ->toBe("modified config\n")
            ->and($result->publishedFragments)
            ->toBeEmpty();
    } finally {
        $harness->cleanup();
    }
});

it('keeps the live Caddy aggregate untouched when candidate validation fails', function (): void {
    [$node] = app_dev_runtime_models();
    $ssh = new AppDevFakeSshExecutor([
        new CommandResult(1, '', 'invalid candidate', 1, false),
    ]);
    $manager = new RemoteAppDevCaddyManager(
        sites: new AppDevSiteRepository,
        renderer: new AppDevCaddyConfigRenderer,
        ssh: app_dev_ssh($ssh),
    );

    expect(fn () => $manager->converge($node))
        ->toThrow(function (RuntimeConvergenceException $exception): void {
            expect($exception->errorCode)->toBe('app-dev.caddy_config_failed');
        });

    $script = $ssh->commands[0]->input ?? '';
    $validation = mb_strpos(haystack: $script, needle: 'caddy validate --config "$published/Caddyfile"');
    $liveSwitch = mb_strpos(
        haystack: $script,
        needle: 'mv -fT -- "$candidate_link" "$live_caddyfile"',
    );

    expect($validation)
        ->toBeInt()
        ->and($liveSwitch)
        ->toBeInt()
        ->and($validation)
        ->toBeLessThan($liveSwitch)
        ->and($script)
        ->toContain('rm -rf -- "$candidate" "$candidate_link"');
});

it('keeps the live DNS fragment untouched when effective validation fails', function (): void {
    app_dev_runtime_models();
    $processes = new AppDevFakeProcessRunner;
    $processes->fail = true;
    $manager = new DnsmasqPrivateDnsManager(new AppDevSiteRepository, $processes);

    expect($manager->converge(...))
        ->toThrow(function (RuntimeConvergenceException $exception): void {
            expect($exception->errorCode)->toBe('app-dev.dns_config_failed');
        });

    $script = $processes->invocations[0]->input ?? '';
    $validation = mb_strpos(
        haystack: $script,
        needle: 'dnsmasq --test --conf-file="$validation/dnsmasq.conf"',
    );
    $liveSwitch = mb_strpos(
        haystack: $script,
        needle: 'mv -fT -- "$candidate" "$managed"',
    );
    $restart = mb_strpos(haystack: $script, needle: 'systemctl restart dnsmasq');

    expect($validation)
        ->toBeInt()
        ->and($liveSwitch)
        ->toBeInt()
        ->and($restart)
        ->toBeInt()
        ->and($validation)
        ->toBeLessThan($liveSwitch)
        ->and($liveSwitch)
        ->toBeLessThan($restart)
        ->and($script)
        ->toContain('trap \'rm -rf -- "$validation"; rm -f -- "$candidate"\' EXIT');
});

/** @return array{Node, Instance, Workspace} */
function app_dev_runtime_models(string $instancePhp = '8.5'): array
{
    $node = Node::query()->create([
        'name' => 'app-dev',
        'status' => LifecycleStatus::Active,
        'public_ssh_host' => '192.0.2.10',
        'wireguard_address' => '10.44.0.3',
        'ssh_user' => 'orbit',
    ]);
    $app = OrbitApp::query()->create([
        'name' => 'Acme',
        'slug' => 'acme',
        'repository_url' => 'git@github.com:acme/site.git',
    ]);
    $instance = Instance::query()->create([
        'app_id' => $app->id,
        'node_id' => $node->id,
        'name' => 'dev',
        'environment' => 'development',
        'checkout_path' => '/home/orbit/apps/acme',
        'document_root' => 'public',
        'php_version' => $instancePhp,
        'hostname' => 'acme.app-dev.orbit',
        'certificate_mode' => CertificateMode::OrbitCa,
        'status' => LifecycleStatus::Active,
    ]);
    $workspace = Workspace::query()->create([
        'instance_id' => $instance->id,
        'name' => 'feature',
        'branch' => 'feature',
        'checkout_path' => '/home/orbit/.orbit/worktrees/acme/feature',
        'hostname' => 'feature.acme.app-dev.orbit',
        'status' => LifecycleStatus::Active,
    ]);

    return [$node, $instance, $workspace];
}

/** @return array{RemoteAppDevSourceManager, AppDevFakeSshExecutor} */
function source_manager(?AppDevSourceOperationLock $lock = null): array
{
    $ssh = new AppDevFakeSshExecutor;
    $lock ??= new class implements AppDevSourceOperationLock {
        public function synchronized(int $nodeId, Closure $operation): mixed
        {
            return $operation();
        }
    };

    return [new RemoteAppDevSourceManager(app_dev_ssh($ssh), $lock), $ssh];
}

function initialise_acl_test_repository(string $path, string $repository): void
{
    $runner = new NativeProcessRunner;
    $initialise = $runner->run(new ProcessInvocation(['git', '-C', $path, 'init']));
    $remote = $runner->run(new ProcessInvocation(['git', '-C', $path, 'remote', 'add', 'origin', $repository]));
    $stage = $runner->run(new ProcessInvocation(['git', '-C', $path, 'add', '.']));
    $commit = $runner->run(new ProcessInvocation([
        'git',
        '-C',
        $path,
        '-c',
        'user.name=Orbit Test',
        '-c',
        'user.email=orbit@example.test',
        'commit',
        '--allow-empty',
        '-m',
        'Initial test commit',
    ]));

    expect($initialise->succeeded())
        ->toBeTrue($initialise->stderr)
        ->and($remote->succeeded())
        ->toBeTrue($remote->stderr)
        ->and($stage->succeeded())
        ->toBeTrue($stage->stderr)
        ->and($commit->succeeded())
        ->toBeTrue($commit->stderr);
}

function run_app_dev_command_locally(RemoteCommand $command, string $root): CommandResult
{
    $arguments = array_map(
        static fn (string $argument): string => str_replace('/home/orbit', $root, $argument),
        $command->arguments,
    );
    $input = str_replace('/home/orbit', $root, $command->input ?? '');
    $input = str_replace(
        ['u:caddy:', 'user:caddy:'],
        ['u:nobody:', 'user:nobody:'],
        $input,
    );

    return new NativeProcessRunner()->run(new ProcessInvocation(
        arguments: $arguments,
        input: $input,
    ));
}

function acl_for(string $path): string
{
    return new NativeProcessRunner()->run(new ProcessInvocation(['getfacl', '-cp', $path]))->stdout;
}

function access_acl_permissions_for(string $user, string $path): ?string
{
    $matched = preg_match(
        '/^user:'.preg_quote(str: $user, delimiter: '/').':([rwx-]{3})/m',
        acl_for($path),
        $matches,
    );

    return $matched === 1 ? $matches[1] : null;
}

function effective_access_acl_permissions_for(string $user, string $path): ?string
{
    $matched = preg_match(
        '/^user:'.preg_quote(str: $user, delimiter: '/').':([rwx-]{3})(?:\s+#effective:([rwx-]{3}))?/m',
        acl_for($path),
        $matches,
    );

    if ($matched !== 1) {
        return null;
    }

    return $matches[2] ?? $matches[1];
}

function setfacl_for(string $user, string $permissions, string $path): void
{
    $result = new NativeProcessRunner()->run(new ProcessInvocation([
        'setfacl',
        '-m',
        "u:{$user}:{$permissions}",
        $path,
    ]));

    expect($result->succeeded())->toBeTrue($result->stderr);
}

function xattr_for(string $path): ?string
{
    $result = new NativeProcessRunner()->run(new ProcessInvocation([
        'getfattr',
        '--only-values',
        '-n',
        'user.orbit.caddy_traversal',
        '--',
        $path,
    ]));

    return $result->succeeded() ? trim($result->stdout) : null;
}

function set_xattr(string $path, string $value): void
{
    $result = new NativeProcessRunner()->run(new ProcessInvocation([
        'setfattr',
        '-n',
        'user.orbit.caddy_traversal',
        '-v',
        $value,
        '--',
        $path,
    ]));

    expect($result->succeeded())->toBeTrue($result->stderr);
}

function zero_site_publisher(AppDevCaddyPublishHarness $harness): AppDevCaddyPublisher
{
    return new AppDevCaddyPublisher(
        versionsDirectory: $harness->etcCaddyPath('orbit-versions'),
        liveCaddyfilePath: $harness->etcCaddyPath('Caddyfile'),
        caddyServiceName: 'caddy',
    );
}

function app_dev_ssh(AppDevFakeSshExecutor $ssh): AppDevSshExecutor
{
    $keys = new class implements SshKeyProvider {
        public function privateKeyPath(): string
        {
            return '/home/orbit/.orbit/ssh/id_ed25519';
        }

        public function publicKey(): string
        {
            return 'ssh-ed25519 AAAA';
        }
    };
    $knownHosts = new class implements KnownHostsStore {
        public function path(): string
        {
            return '/home/orbit/.orbit/ssh/known_hosts';
        }

        public function put(string $host, int $port, HostKey $key): void {}
    };

    return new AppDevSshExecutor($ssh, $keys, $knownHosts);
}
