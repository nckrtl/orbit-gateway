<?php

declare(strict_types=1);

namespace App\Infrastructure\WireGuard;

use App\Domain\Nodes\NodeProvisioningException;
use App\Domain\WireGuard\GatewayPeerProjectionManager;
use App\Infrastructure\Processes\CommandResult;
use App\Infrastructure\Ssh\RemoteCommand;
use App\Infrastructure\Ssh\SshConnection;
use App\Infrastructure\Ssh\SshExecutor;
use App\Models\Node;

final readonly class NativeWireGuardPeerConverger implements WireGuardPeerConverger
{
    public function __construct(
        private VpnConfigurationRepository $configuration,
        private GatewayPeerProjectionManager $gatewayPeers,
        private SshExecutor $ssh,
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
                    exec 9>/run/lock/orbit-wireguard-peer.lock
                    flock -w 30 9
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
        $this->gatewayPeers->converge($node);

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
                input: <<<'BASH_WRAP'
                    server_public_key=$1
                    endpoint=$2
                    address=$3
                    subnet=$4
                    dns_server=$5
                    domain=$6
                    dns_mode=$7
                    exec 9>/run/lock/orbit-wireguard-peer.lock
                    flock -w 30 9
                    private_key=$(cat /etc/wireguard/orbit.key)
                    candidate=/etc/wireguard/orbit-candidate.conf
                    live=/etc/wireguard/orbit.conf
                    backup=/etc/wireguard/.orbit.conf.rollback
                    dns_state=/etc/wireguard/orbit.dns-link
                    dns_state_candidate=/etc/wireguard/.orbit.dns-link.candidate
                    printf -v dns_server_escaped '%q' "$dns_server"
                    printf -v domain_escaped '%q' "~$domain"
                    trap 'rm -f -- "$candidate" "$dns_state_candidate"' EXIT

                    case "$dns_mode" in
                        wireguard|underlay) ;;
                        *) exit 1 ;;
                    esac

                    dns_hooks=
                    if [ "$dns_mode" = wireguard ]; then
                        dns_hooks="PostUp = resolvectl dns %i $dns_server_escaped; resolvectl domain %i $domain_escaped"$'\n'"PreDown = resolvectl revert %i"
                    fi

                    old_dns_link=
                    old_dns_server=
                    old_dns_domain=
                    if [ -s "$dns_state" ]; then
                        mapfile -t old_dns_state < "$dns_state"
                        old_dns_link=${old_dns_state[0]:-}
                        old_dns_server=${old_dns_state[1]:-$dns_server}
                        old_dns_domain=${old_dns_state[2]:-$domain}
                        if [[ ! "$old_dns_link" =~ ^[A-Za-z0-9_.:+-]+$ ]] \
                            || [[ ! "$old_dns_server" =~ ^[A-Fa-f0-9:.]+$ ]] \
                            || [[ ! "$old_dns_domain" =~ ^[A-Za-z0-9.-]+$ ]]; then
                            old_dns_link=
                            old_dns_server=
                            old_dns_domain=
                        fi
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
                    rm -f -- "$backup"
                    if [ -f "$live" ]; then
                        cp --preserve=mode,ownership -- "$live" "$backup"
                    fi
                    restore_previous() {
                        if [ -f "$backup" ]; then
                            mv -fT -- "$backup" "$live"
                            systemctl restart wg-quick@orbit || true
                        else
                            rm -f -- "$live"
                            systemctl stop wg-quick@orbit || true
                        fi
                    }
                    dns_link=
                    restore_dns() {
                        if [[ "$dns_link" =~ ^[A-Za-z0-9_.:+-]+$ ]]; then
                            resolvectl revert "$dns_link" || true
                        fi
                        if [ -n "$old_dns_link" ]; then
                            resolvectl dns "$old_dns_link" "$old_dns_server" || true
                            resolvectl domain "$old_dns_link" "~$old_dns_domain" || true
                        fi
                    }
                    if ! mv -f -- "$candidate" "$live"; then
                        rm -f -- "$backup"
                        exit 1
                    fi
                    if ! systemctl enable wg-quick@orbit; then
                        restore_previous
                        exit 1
                    fi
                    if ! systemctl restart wg-quick@orbit; then
                        restore_previous
                        exit 1
                    fi

                    if [ "$dns_mode" = underlay ]; then
                        route=$(ip -o route get "$dns_server")
                        if [[ "$route" =~ [[:space:]]dev[[:space:]]([^[:space:]]+) ]]; then
                            dns_link=${BASH_REMATCH[1]}
                        else
                            echo 'Could not resolve DNS interface.' >&2
                            restore_dns
                            restore_previous
                            exit 1
                        fi
                        if ! resolvectl dns "$dns_link" "$dns_server"; then
                            restore_dns
                            restore_previous
                            exit 1
                        fi
                        if ! resolvectl domain "$dns_link" "~$domain"; then
                            restore_dns
                            restore_previous
                            exit 1
                        fi
                    else
                        dns_link=orbit
                    fi

                    if [ -n "$old_dns_link" ] && [ "$old_dns_link" != "$dns_link" ]; then
                        resolvectl revert "$old_dns_link" || true
                    fi
                    if ! printf '%s\n%s\n%s\n' "$dns_link" "$dns_server" "$domain" > "$dns_state_candidate"; then
                        restore_dns
                        restore_previous
                        exit 1
                    fi
                    chmod 0600 "$dns_state_candidate"
                    if ! mv -f -- "$dns_state_candidate" "$dns_state"; then
                        restore_dns
                        restore_previous
                        exit 1
                    fi
                    if ! active_public_key=$(wg show orbit public-key); then
                        restore_dns
                        restore_previous
                        exit 1
                    fi
                    rm -f -- "$backup"
                    trap - EXIT
                    printf '%s\n' "$active_public_key"
                    BASH_WRAP,
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
