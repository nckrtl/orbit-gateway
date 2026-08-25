<?php

declare(strict_types=1);

use App\Actions\Gateway\BootstrapGatewayAction;
use App\Data\Gateway\BootstrapGatewayData;
use App\Domain\Nodes\RoleName;
use App\Domain\Settings\SettingRepository;
use App\Domain\Settings\SettingScope;
use App\Domain\Settings\SettingScopeType;
use App\Infrastructure\Files\ProtectedFileWriter;
use App\Infrastructure\Processes\NativeProcessRunner;
use App\Models\Node;
use Illuminate\Filesystem\Filesystem;
use Illuminate\Support\Str;

it('initializes the portable gateway authority idempotently', function (): void {
    $orbitHome = sys_get_temp_dir().'/orbit-bootstrap-'.Str::uuid();
    $action = new BootstrapGatewayAction(
        assignRole: app(App\Actions\Nodes\AssignRoleAction::class),
        settings: app(SettingRepository::class),
        processes: new NativeProcessRunner,
        files: new ProtectedFileWriter,
        orbitHome: $orbitHome,
    );
    $data = new BootstrapGatewayData(
        publicHost: '85.9.218.89',
        wireguardAddress: '10.44.0.1',
        wireguardSubnet: '10.44.0.0/24',
        wireguardEndpoint: '85.9.218.89:51820',
        dnsServer: '10.44.0.1',
        domain: 'test',
        privateInterface: 'eth3',
    );

    try {
        $first = $action->execute($data);
        $second = $action->execute($data);
        $scope = new SettingScope(SettingScopeType::Gateway);

        expect($first->is($second))
            ->toBeTrue()
            ->and($first->roles()->pluck('role')->all())
            ->toContain(RoleName::Gateway, RoleName::Vpn)
            ->and(is_file($orbitHome.'/ssh/id_ed25519'))
            ->toBeTrue()
            ->and(is_file($orbitHome.'/wireguard/private.key'))
            ->toBeTrue()
            ->and(is_file($orbitHome.'/ca/root.key'))
            ->toBeTrue()
            ->and(is_file($orbitHome.'/ca/root.pem'))
            ->toBeTrue()
            ->and(fileperms($orbitHome.'/ca/root.key') & 0o777)
            ->toBe(0o600)
            ->and(app(SettingRepository::class)->get($scope, 'vpn.private_interface'))
            ->toBe('eth3')
            ->and(Node::query()->count())
            ->toBe(1);
    } finally {
        new Filesystem()->deleteDirectory($orbitHome);
    }
});
