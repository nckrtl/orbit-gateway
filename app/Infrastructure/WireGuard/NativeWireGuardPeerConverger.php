<?php

declare(strict_types=1);

namespace App\Infrastructure\WireGuard;

use App\Domain\Nodes\NodeProvisioningException;
use App\Infrastructure\Files\ProtectedFileWriter;
use App\Infrastructure\Processes\CommandResult;
use App\Infrastructure\Processes\ProcessInvocation;
use App\Infrastructure\Processes\ProcessRunner;
use App\Infrastructure\Ssh\RemoteCommand;
use App\Infrastructure\Ssh\SshConnection;
use App\Infrastructure\Ssh\SshExecutor;
use App\Models\Node;

/** @mago-expect lint:excessive-parameter-list */
final readonly class NativeWireGuardPeerConverger implements WireGuardPeerConverger
{
    private const string GENERATED_SERVER_CONFIG_PATH = '/generated/wireguard/orbit.conf';

    private const string CANDIDATE_SERVER_CONFIG_PATH = '/etc/wireguard/orbit-candidate.conf';

    private const string LIVE_SERVER_CONFIG_PATH = '/etc/wireguard/orbit.conf';

    public function __construct(
        private VpnConfigurationRepository $configuration,
        private WireGuardServerConfigRenderer $serverRenderer,
        private ProtectedFileWriter $files,
        private ProcessRunner $processes,
        private SshExecutor $ssh,
        private string $orbitHome,
    ) {}

    public function converge(Node $node, SshConnection $connection): void
    {
        $vpn = $this->configuration->forPeer($node);
        $keyResult = $this->ssh->execute(
            $connection,
            new RemoteCommand(
                arguments: ['sudo', 'bash', '-seu'],
                input: <<<'BASH'
                    install -d -m 0700 /etc/wireguard
                    umask 077
                    if [ ! -s /etc/wireguard/orbit.key ]; then
                        wg genkey > /etc/wireguard/orbit.key
                    fi
                    wg pubkey < /etc/wireguard/orbit.key > /etc/wireguard/orbit.public
                    cat /etc/wireguard/orbit.public
                    BASH,
            ),
        );
        $publicKey = trim($keyResult->stdout);

        if (! $keyResult->succeeded() || preg_match('/^[A-Za-z0-9+\/]{43}=$/', $publicKey) !== 1) {
            throw $this->failure(
                step: 'wireguard-peer-key',
                errorCode: 'vpn.peer_key_failed',
                message: "Could not generate a WireGuard key on node [{$node->name}].",
                result: $keyResult,
            );
        }

        $node->update(['wireguard_public_key' => $publicKey]);
        $serverConfig = $this->serverRenderer->render(
            $vpn,
            Node::query()->whereNotNull('wireguard_public_key')->get(),
        );
        $generatedPath = rtrim(string: $this->orbitHome, characters: '/').self::GENERATED_SERVER_CONFIG_PATH;
        $this->files->put($generatedPath, $serverConfig);

        $this->installServerConfig($generatedPath);
        $this->runLocal(
            'wireguard-server-enable',
            'vpn.server_start_failed',
            ['sudo', 'systemctl', 'enable', 'wg-quick@orbit'],
        );
        $this->runLocal(
            'wireguard-server-restart',
            'vpn.server_start_failed',
            ['sudo', 'systemctl', 'restart', 'wg-quick@orbit'],
        );

        $peerResult = $this->ssh->execute(
            $connection,
            new RemoteCommand(
                arguments: [
                    'sudo',
                    'bash',
                    '-seu',
                    '--',
                    $vpn->serverPublicKey,
                    $vpn->endpoint,
                    $vpn->peerAddress,
                    $vpn->subnet,
                    $vpn->dnsServer,
                    $vpn->domain,
                    $vpn->dnsThroughWireGuard ? 'wireguard' : 'underlay',
                ],
                input: <<<'BASH'
                    server_public_key=$1
                    endpoint=$2
                    address=$3
                    subnet=$4
                    dns_server=$5
                    domain=$6
                    dns_mode=$7
                    private_key=$(cat /etc/wireguard/orbit.key)
                    candidate=/etc/wireguard/orbit-candidate.conf
                    dns_state=/etc/wireguard/orbit.dns-link
                    printf -v dns_server_escaped '%q' "$dns_server"
                    printf -v domain_escaped '%q' "~$domain"
                    trap 'rm -f -- "$candidate"' EXIT

                    case "$dns_mode" in
                        wireguard|underlay) ;;
                        *) exit 1 ;;
                    esac

                    if [ -s "$dns_state" ]; then
                        old_dns_link=$(cat "$dns_state")
                        if [[ "$old_dns_link" =~ ^[A-Za-z0-9_.:+-]+$ ]]; then
                            resolvectl revert "$old_dns_link" || true
                        fi
                        rm -f -- "$dns_state"
                    fi

                    dns_hooks=
                    if [ "$dns_mode" = wireguard ]; then
                        dns_hooks="PostUp = resolvectl dns %i $dns_server_escaped; resolvectl domain %i $domain_escaped"$'\n'"PreDown = resolvectl revert %i"
                    fi

                    cat > "$candidate" <<EOF
                    [Interface]
                    PrivateKey = $private_key
                    Address = $address
                    $dns_hooks

                    [Peer]
                    PublicKey = $server_public_key
                    Endpoint = $endpoint
                    AllowedIPs = $subnet
                    PersistentKeepalive = 25
                    EOF

                    chown root:root "$candidate"
                    chmod 0600 "$candidate"
                    wg-quick strip "$candidate" >/dev/null
                    mv -f -- "$candidate" /etc/wireguard/orbit.conf
                    trap - EXIT
                    systemctl enable wg-quick@orbit
                    systemctl restart wg-quick@orbit

                    if [ "$dns_mode" = underlay ]; then
                        route=$(ip -o route get "$dns_server")
                        if [[ "$route" =~ [[:space:]]dev[[:space:]]([^[:space:]]+) ]]; then
                            dns_link=${BASH_REMATCH[1]}
                        else
                            echo 'Could not resolve DNS interface.' >&2
                            exit 1
                        fi
                        resolvectl dns "$dns_link" "$dns_server"
                        resolvectl domain "$dns_link" "~$domain"
                    else
                        dns_link=orbit
                    fi

                    printf '%s\n' "$dns_link" > "$dns_state"
                    wg show orbit public-key
                    BASH,
            ),
        );

        if (! $peerResult->succeeded()) {
            throw $this->failure(
                step: 'wireguard-peer-install',
                errorCode: 'vpn.peer_config_failed',
                message: "Could not configure WireGuard on node [{$node->name}].",
                result: $peerResult,
            );
        }
    }

    private function installServerConfig(string $generatedPath): void
    {
        try {
            $this->runLocal(
                'wireguard-server-install',
                'vpn.server_config_install_failed',
                [
                    'sudo',
                    'install',
                    '-D',
                    '-o',
                    'root',
                    '-g',
                    'root',
                    '-m',
                    '0600',
                    '--',
                    $generatedPath,
                    self::CANDIDATE_SERVER_CONFIG_PATH,
                ],
            );
            $this->runLocal(
                'wireguard-server-validate',
                'vpn.server_config_invalid',
                ['sudo', 'wg-quick', 'strip', self::CANDIDATE_SERVER_CONFIG_PATH],
            );
            $this->runLocal(
                'wireguard-server-install',
                'vpn.server_config_install_failed',
                [
                    'sudo',
                    'mv',
                    '-f',
                    '--',
                    self::CANDIDATE_SERVER_CONFIG_PATH,
                    self::LIVE_SERVER_CONFIG_PATH,
                ],
            );
        } catch (NodeProvisioningException $exception) {
            $this->cleanupCandidateServerConfig();

            throw $exception;
        }
    }

    /** @param non-empty-list<string> $arguments */
    private function runLocal(string $step, string $errorCode, array $arguments): void
    {
        $result = $this->processes->run(new ProcessInvocation($arguments));

        if (! $result->succeeded()) {
            throw $this->failure(
                step: $step,
                errorCode: $errorCode,
                message: 'Could not converge the gateway WireGuard service.',
                result: $result,
            );
        }
    }

    private function cleanupCandidateServerConfig(): void
    {
        $this->processes->run(new ProcessInvocation([
            'sudo',
            'rm',
            '-f',
            '--',
            self::CANDIDATE_SERVER_CONFIG_PATH,
        ]));
    }

    private function failure(
        string $step,
        string $errorCode,
        string $message,
        CommandResult $result,
    ): NodeProvisioningException {
        return new NodeProvisioningException(
            step: $step,
            errorCode: $errorCode,
            message: $message,
            result: $result,
        );
    }
}
