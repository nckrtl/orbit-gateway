<?php

declare(strict_types=1);

namespace App\Infrastructure\MacOs;

use App\Data\Nodes\MacOsAppDevSetupFactsData;
use App\Domain\MacOs\MacOsAppDevSetupPlan;
use App\Domain\MacOs\MacOsAppDevSetupRenderer;
use App\Domain\Nodes\RoleName;
use App\Infrastructure\Ssh\SshKeyProvider;
use App\Models\Node;
use App\Models\NodeRole;
use Closure;
use UnexpectedValueException;

/** @mago-expect lint:cyclomatic-complexity Rendering validates every fixed setup identity before interpolation. */
final readonly class MacOsAppDevSetupScriptRenderer implements MacOsAppDevSetupRenderer
{
    /** @param (Closure(): string)|null $gatewayAddressResolver */
    public function __construct(
        private SshKeyProvider $sshKeys,
        private ?Closure $gatewayAddressResolver = null,
    ) {}

    public function render(
        Node $node,
        NodeRole $assignment,
        MacOsAppDevSetupFactsData $facts,
    ): MacOsAppDevSetupPlan {
        $brewPrefix = match ($facts->architecture) {
            'arm64' => '/opt/homebrew',
            'x86_64' => '/usr/local',
            default => throw new UnexpectedValueException('The macOS architecture is not supported.'),
        };

        $this->assertSetupState($node, $assignment, $facts);
        $gatewayAddress = $this->gatewayAddress();
        $publicKey = $this->sshKeys->publicKey();

        if (preg_match('/\Assh-(?:ed25519|rsa|ecdsa-[^ ]+) [A-Za-z0-9+\/=]+(?: .*)?\z/D', $publicKey) !== 1) {
            throw new UnexpectedValueException('The Gateway SSH public key is invalid.');
        }

        $restrictedKey =
            "from=\"{$gatewayAddress}\",no-agent-forwarding,no-port-forwarding,"
            ."no-X11-forwarding,no-pty,no-user-rc {$publicKey}";
        $script = strtr($this->scriptTemplate(), [
            '__EXPECTED_ARCHITECTURE__' => $this->shellQuote($facts->architecture),
            '__EXPECTED_USERNAME__' => $this->shellQuote($facts->username),
            '__EXPECTED_HOME__' => $this->shellQuote($facts->homeDirectory),
            '__WIREGUARD_ADDRESS__' => $this->shellQuote((string) $node->wireguard_address),
            '__NODE_TLD__' => $this->shellQuote((string) $node->tld),
            '__GATEWAY_WIREGUARD_ADDRESS__' => $this->shellQuote($gatewayAddress),
            '__EXPECTED_BREW_PREFIX__' => $this->shellQuote($brewPrefix),
            '__RESTRICTED_GATEWAY_KEY__' => $this->shellQuote($restrictedKey),
        ]);

        return new MacOsAppDevSetupPlan(
            summary: implode(PHP_EOL, [
                'Orbit will make these approved local macOS app-dev changes:',
                '- Install Homebrew in its supported default prefix when it is absent.',
                '- Enable Remote Login when it is disabled.',
                '- Install the Orbit PF redirect for this WireGuard address.',
                '- Install the root dnsmasq service on 127.0.0.1:53.',
                '- Install the local resolver for this node TLD.',
                '- Install user-owned Orbit files and LaunchAgents.',
            ]),
            script: $script,
        );
    }

    private function assertSetupState(
        Node $node,
        NodeRole $assignment,
        MacOsAppDevSetupFactsData $facts,
    ): void {
        if ($node->platform !== 'darwin' || $facts->platform !== 'darwin') {
            throw new UnexpectedValueException('The setup target must be a Darwin node.');
        }

        if (
            $node->architecture !== $facts->architecture
            || $node->ssh_user !== $facts->username
            || $facts->homeDirectory !== "/Users/{$node->ssh_user}"
        ) {
            throw new UnexpectedValueException('The macOS setup facts do not match the stored node.');
        }

        if ($assignment->role !== RoleName::AppDev) {
            throw new UnexpectedValueException('The setup assignment must be the app-dev role.');
        }

        if (
            ! is_string($node->wireguard_address)
            || filter_var($node->wireguard_address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false
        ) {
            throw new UnexpectedValueException('The macOS WireGuard address is invalid.');
        }

        if (! is_string($node->tld) || preg_match('/\A[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\z/D', $node->tld) !== 1) {
            throw new UnexpectedValueException('The macOS development TLD is invalid.');
        }
    }

    private function gatewayAddress(): string
    {
        if ($this->gatewayAddressResolver instanceof Closure) {
            $address = ($this->gatewayAddressResolver)();

            if (filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
                throw new UnexpectedValueException('The Gateway WireGuard address is invalid.');
            }

            return $address;
        }

        $gateways = Node::query()
            ->whereHas('roles', static fn ($query) => $query->where('role', RoleName::Gateway->value))
            ->get();

        if ($gateways->count() !== 1) {
            throw new UnexpectedValueException('Gateway state must contain exactly one Gateway-role node.');
        }

        $address = $gateways->sole()->wireguard_address;

        if (! is_string($address) || filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
            throw new UnexpectedValueException('The Gateway WireGuard address is invalid.');
        }

        return $address;
    }

    private function shellQuote(string $value): string
    {
        return "'".str_replace(search: "'", replace: "'\"'\"'", subject: $value)."'";
    }

    private function scriptTemplate(): string
    {
        return <<<'BASH'
            #!/bin/bash
            set -euo pipefail

            EXPECTED_PLATFORM='darwin'
            EXPECTED_ARCHITECTURE=__EXPECTED_ARCHITECTURE__
            EXPECTED_USERNAME=__EXPECTED_USERNAME__
            EXPECTED_HOME=__EXPECTED_HOME__
            WIREGUARD_ADDRESS=__WIREGUARD_ADDRESS__
            NODE_TLD=__NODE_TLD__
            GATEWAY_WIREGUARD_ADDRESS=__GATEWAY_WIREGUARD_ADDRESS__
            EXPECTED_BREW_PREFIX=__EXPECTED_BREW_PREFIX__
            RESTRICTED_GATEWAY_KEY=__RESTRICTED_GATEWAY_KEY__
            HOMEBREW_INSTALLER_URL='https://raw.githubusercontent.com/Homebrew/install/b9990527570f7e07d5393f37447b8293ec0a78de/install.sh'
            HOMEBREW_INSTALLER_SHA256='12479a24be3f5307eecac7cde670fad7118640f031229e964f544b1367b52a41'

            PF_ANCHOR='/etc/pf.anchors/com.orbit.app-dev'
            PF_CONFIG='/etc/pf.conf'
            DNSMASQ_DIRECTORY='/Library/Application Support/Orbit/app-dev'
            DNSMASQ_CONFIG='/Library/Application Support/Orbit/app-dev/dnsmasq.conf'
            DNSMASQ_PLIST='/Library/LaunchDaemons/com.orbit.dnsmasq.plist'
            RESOLVER_PATH="/etc/resolver/${NODE_TLD}"
            ORBIT_HOME="${EXPECTED_HOME}/.orbit"
            AUTHORIZED_KEYS="${EXPECTED_HOME}/.ssh/authorized_keys"
            CADDY_PLIST="${EXPECTED_HOME}/Library/LaunchAgents/com.orbit.caddy.plist"

            WORK_DIRECTORY="$(/usr/bin/mktemp -d "${TMPDIR:-/tmp}/orbit-app-dev.XXXXXX")"
            /bin/chmod 0700 "${WORK_DIRECTORY}"
            HOMEBREW_INSTALLER="${WORK_DIRECTORY}/homebrew-install.sh"
            PHP_AGENT_RECORDS="${WORK_DIRECTORY}/php-agent-records"
            PHP_AGENTS_LOADED="${WORK_DIRECTORY}/php-agents-loaded"
            : > "${PHP_AGENT_RECORDS}"
            : > "${PHP_AGENTS_LOADED}"

            SETUP_SUCCEEDED=0
            HOMEBREW_INSTALLED_THIS_ATTEMPT=0
            PROTECTED_SNAPSHOTS_READY=0
            AUTHORIZED_KEYS_SNAPSHOTTED=0
            CADDY_SNAPSHOTTED=0
            REMOTE_LOGIN_WAS_ENABLED=0
            REMOTE_LOGIN_CHANGED=0
            PF_WAS_ENABLED=0
            DNSMASQ_WAS_LOADED=0
            CADDY_WAS_LOADED=0
            RECOVERY_FAILED=0
            USER_ID=''

            recovery_issue() {
                RECOVERY_FAILED=1
                /usr/bin/printf '%s\n' "$1" >&2
            }

            launchctl_native_absence() {
                launchctl_output="$1"
                launchctl_service="$2"
                case "${launchctl_output}" in
                    'Could not find service'|'service could not be found'|'No such process'|'Boot-out failed: 3: No such process') return 0 ;;
                esac

                launchctl_domain="${launchctl_service%%/*}"
                launchctl_remainder="${launchctl_service#*/}"
                if [ "${launchctl_domain}" = 'gui' ] && [ "${launchctl_remainder}" != "${launchctl_service}" ]; then
                    launchctl_user_id="${launchctl_remainder%%/*}"
                    launchctl_label="${launchctl_remainder#*/}"
                    launchctl_canonical="Could not find service \"${launchctl_label}\" in domain for user gui: ${launchctl_user_id}"
                elif [ "${launchctl_domain}" = 'system' ]; then
                    launchctl_label="${launchctl_service#*/}"
                    launchctl_canonical="Could not find service \"${launchctl_label}\" in domain for system"
                else
                    return 1
                fi

                [ "${launchctl_output}" = "${launchctl_canonical}" ] \
                    || [ "${launchctl_output}" = "Bad request.
            ${launchctl_canonical}" ]
            }

            launchctl_recognized_state() {
                /usr/bin/printf '%s\n' "$1" \
                    | /usr/bin/awk '
                        /^[[:space:]]*state[[:space:]]*=/ {
                            total_states++
                        }
                        /^[[:space:]]*state = (running|not running|stopped|waiting)[[:space:]]*$/ {
                            recognized_states++
                        }
                        END { exit total_states == 1 && recognized_states == 1 ? 0 : 1 }
                    '
            }

            rollback_user_bootout() {
                rollback_plist="$1"
                rollback_service="$2"
                rollback_category="$3"
                if rollback_output="$(/bin/launchctl bootout "gui/${USER_ID}" "${rollback_plist}" 2>&1)"; then
                    return 0
                fi
                launchctl_native_absence "${rollback_output}" "${rollback_service}" \
                    || recovery_issue "${rollback_category}"
            }

            rollback_system_bootout() {
                rollback_service="$1"
                rollback_category="$2"
                if rollback_output="$(/usr/bin/sudo /bin/launchctl bootout "${rollback_service}" 2>&1)"; then
                    return 0
                fi
                launchctl_native_absence "${rollback_output}" "${rollback_service}" \
                    || recovery_issue "${rollback_category}"
            }

            restore_pf_state() {
                if [ "${PF_WAS_ENABLED}" -eq 1 ]; then
                    /usr/bin/sudo /sbin/pfctl -e >/dev/null 2>&1
                    expected_pf_status='Status: Enabled'
                else
                    /usr/bin/sudo /sbin/pfctl -d >/dev/null 2>&1
                    expected_pf_status='Status: Disabled'
                fi
                restored_pf_status="$(/usr/bin/sudo /sbin/pfctl -s info 2>/dev/null)"
                /usr/bin/printf '%s\n' "${restored_pf_status}" \
                    | /usr/bin/grep -Eq "^[[:space:]]*${expected_pf_status}[[:space:]]*$"
            }

            snapshot_root_file() {
                snapshot_name="$1"
                source_path="$2"
                if /usr/bin/sudo /bin/test -e "${source_path}"; then
                    /usr/bin/sudo /bin/cp -p "${source_path}" "${WORK_DIRECTORY}/${snapshot_name}"
                    /usr/bin/sudo /usr/bin/touch "${WORK_DIRECTORY}/${snapshot_name}.exists"
                fi
            }

            restore_root_file() {
                snapshot_name="$1"
                destination_path="$2"
                if /usr/bin/sudo /bin/test -e "${WORK_DIRECTORY}/${snapshot_name}.exists"; then
                    /usr/bin/sudo /bin/cp -p "${WORK_DIRECTORY}/${snapshot_name}" "${destination_path}" || return 1
                else
                    /usr/bin/sudo /bin/rm -f "${destination_path}" || return 1
                fi
            }

            snapshot_user_file() {
                snapshot_name="$1"
                source_path="$2"
                if /bin/test -e "${source_path}"; then
                    /bin/cp -p "${source_path}" "${WORK_DIRECTORY}/${snapshot_name}"
                    /usr/bin/touch "${WORK_DIRECTORY}/${snapshot_name}.exists"
                fi
            }

            restore_user_file() {
                snapshot_name="$1"
                destination_path="$2"
                if /bin/test -e "${WORK_DIRECTORY}/${snapshot_name}.exists"; then
                    /bin/cp -p "${WORK_DIRECTORY}/${snapshot_name}" "${destination_path}" || return 1
                else
                    /bin/rm -f "${destination_path}" || return 1
                fi
            }

            snapshot_remote_login() { :; }
            install_homebrew() { :; }
            enable_remote_login() { :; }
            install_pf() { :; }
            install_dnsmasq() { :; }
            install_resolver() { :; }
            install_user_state() { :; }
            verify_local_state() { :; }

            restore_user_services() {
                if [ "${CADDY_SNAPSHOTTED}" -eq 1 ]; then
                    rollback_user_bootout \
                        "${CADDY_PLIST}" \
                        "gui/${USER_ID}/com.orbit.caddy" \
                        'recovery:caddy-state-restore-failed'
                    restore_user_file 'caddy-plist' "${CADDY_PLIST}" \
                        || recovery_issue 'recovery:caddy-definition-restore-failed'
                    if [ "${CADDY_WAS_LOADED}" -eq 1 ]; then
                        /bin/launchctl bootstrap "gui/${USER_ID}" "${CADDY_PLIST}" >/dev/null 2>&1 \
                            || recovery_issue 'recovery:caddy-state-restore-failed'
                    fi
                fi

                while IFS='|' read -r backup_name plist_path label; do
                    [ -n "${plist_path}" ] || continue
                    rollback_user_bootout \
                        "${plist_path}" \
                        "gui/${USER_ID}/${label}" \
                        'recovery:php-state-restore-failed'
                    restore_user_file "${backup_name}" "${plist_path}" \
                        || recovery_issue 'recovery:php-definition-restore-failed'
                    if /usr/bin/grep -Fqx "${label}" "${PHP_AGENTS_LOADED}"; then
                        /bin/launchctl bootstrap "gui/${USER_ID}" "${plist_path}" >/dev/null 2>&1 \
                            || recovery_issue 'recovery:php-state-restore-failed'
                    fi
                done < "${PHP_AGENT_RECORDS}"

                if [ "${AUTHORIZED_KEYS_SNAPSHOTTED}" -eq 1 ]; then
                    restore_user_file 'authorized-keys' "${AUTHORIZED_KEYS}" \
                        || recovery_issue 'recovery:authorized-keys-restore-failed'
                fi
            }

            restore_protected_state() {
                rollback_system_bootout \
                    'system/com.orbit.dnsmasq' \
                    'recovery:dnsmasq-state-restore-failed'
                restore_root_file 'dnsmasq-config' "${DNSMASQ_CONFIG}" \
                    || recovery_issue 'recovery:dnsmasq-config-restore-failed'
                restore_root_file 'dnsmasq-plist' "${DNSMASQ_PLIST}" \
                    || recovery_issue 'recovery:dnsmasq-plist-restore-failed'
                if [ "${DNSMASQ_WAS_LOADED}" -eq 1 ]; then
                    /usr/bin/sudo /bin/launchctl bootstrap system "${DNSMASQ_PLIST}" >/dev/null 2>&1 \
                        || recovery_issue 'recovery:dnsmasq-state-restore-failed'
                fi

                restore_root_file 'resolver' "${RESOLVER_PATH}" \
                    || recovery_issue 'recovery:resolver-restore-failed'
                restore_root_file 'pf-anchor' "${PF_ANCHOR}" \
                    || recovery_issue 'recovery:pf-anchor-restore-failed'
                restore_root_file 'pf-config' "${PF_CONFIG}" \
                    || recovery_issue 'recovery:pf-config-restore-failed'
                if /usr/bin/sudo /sbin/pfctl -vnf "${PF_CONFIG}" >/dev/null 2>&1; then
                    /usr/bin/sudo /sbin/pfctl -f "${PF_CONFIG}" >/dev/null 2>&1 \
                        || recovery_issue 'recovery:pf-state-restore-failed'
                    restore_pf_state || recovery_issue 'recovery:pf-state-restore-failed'
                else
                    recovery_issue 'recovery:pf-validation-failed'
                fi

                if [ "${REMOTE_LOGIN_CHANGED}" -eq 1 ] && [ "${REMOTE_LOGIN_WAS_ENABLED}" -eq 0 ]; then
                    if /usr/bin/sudo /usr/sbin/systemsetup -setremotelogin off >/dev/null 2>&1; then
                        /usr/bin/printf '%s\n' 'recovery:remote-login-restored' >&2
                    else
                        recovery_issue 'recovery:remote-login-restore-failed'
                    fi
                fi
            }

            cleanup() {
                exit_code="$1"
                trap - EXIT HUP INT TERM
                set +e
                if [ "${SETUP_SUCCEEDED}" -ne 1 ]; then
                    if [ -n "${USER_ID}" ]; then
                        restore_user_services
                    fi
                    if [ "${PROTECTED_SNAPSHOTS_READY}" -eq 1 ]; then
                        restore_protected_state
                    fi
                    if [ "${HOMEBREW_INSTALLED_THIS_ATTEMPT}" -eq 1 ]; then
                        /usr/bin/printf '%s\n' 'recovery:homebrew-preserved' >&2
                    fi
                fi
                /bin/rm -f "${HOMEBREW_INSTALLER}"
                /bin/rm -rf "${WORK_DIRECTORY}"
                if [ "${RECOVERY_FAILED}" -eq 1 ] && [ "${exit_code}" -eq 0 ]; then
                    exit_code=1
                fi
                exit "${exit_code}"
            }

            trap 'cleanup $?' EXIT
            trap 'exit 129' HUP
            trap 'exit 130' INT
            trap 'exit 143' TERM

            actual_platform="$(/usr/bin/uname -s)"
            [ "${actual_platform}" = 'Darwin' ] || { /usr/bin/printf '%s\n' 'setup:platform-mismatch' >&2; exit 1; }
            actual_architecture="$(/usr/bin/uname -m)"
            [ "${actual_architecture}" = "${EXPECTED_ARCHITECTURE}" ] \
                || { /usr/bin/printf '%s\n' 'setup:architecture-mismatch' >&2; exit 1; }
            actual_username="$(/usr/bin/id -un)"
            [ "${actual_username}" = "${EXPECTED_USERNAME}" ] \
                || { /usr/bin/printf '%s\n' 'setup:identity-mismatch' >&2; exit 1; }
            [ "${HOME}" = "${EXPECTED_HOME}" ] \
                || { /usr/bin/printf '%s\n' 'setup:home-mismatch' >&2; exit 1; }
            USER_ID="$(/usr/bin/id -u)"

            snapshot_remote_login
            remote_login_status="$(/usr/bin/sudo /usr/sbin/systemsetup -getremotelogin 2>/dev/null)"
            case "${remote_login_status}" in
                *On) REMOTE_LOGIN_WAS_ENABLED=1 ;;
                *Off) REMOTE_LOGIN_WAS_ENABLED=0 ;;
                *) /usr/bin/printf '%s\n' 'setup:remote-login-state-unavailable' >&2; exit 1 ;;
            esac

            snapshot_root_file 'pf-anchor' "${PF_ANCHOR}"
            snapshot_root_file 'pf-config' "${PF_CONFIG}"
            snapshot_root_file 'dnsmasq-config' "${DNSMASQ_CONFIG}"
            snapshot_root_file 'dnsmasq-plist' "${DNSMASQ_PLIST}"
            snapshot_root_file 'resolver' "${RESOLVER_PATH}"
            pf_status="$(/usr/bin/sudo /sbin/pfctl -s info 2>/dev/null)"
            case "${pf_status}" in
                *'Status: Enabled'*) PF_WAS_ENABLED=1 ;;
                *'Status: Disabled'*) PF_WAS_ENABLED=0 ;;
                *) /usr/bin/printf '%s\n' 'setup:pf-state-unavailable' >&2; exit 1 ;;
            esac
            if dnsmasq_launchctl_state="$(/usr/bin/sudo /bin/launchctl print system/com.orbit.dnsmasq 2>&1)"; then
                launchctl_recognized_state "${dnsmasq_launchctl_state}" \
                    || { /usr/bin/printf '%s\n' 'setup:launchctl-state-unavailable' >&2; exit 1; }
                DNSMASQ_WAS_LOADED=1
            elif ! launchctl_native_absence "${dnsmasq_launchctl_state}" 'system/com.orbit.dnsmasq'; then
                /usr/bin/printf '%s\n' 'setup:launchctl-state-unavailable' >&2
                exit 1
            fi
            PROTECTED_SNAPSHOTS_READY=1

            install_homebrew
            if [ ! -x "${EXPECTED_BREW_PREFIX}/bin/brew" ]; then
                if command -v brew >/dev/null 2>&1; then
                    discovered_brew_prefix="$(brew --prefix)"
                    [ "${discovered_brew_prefix}" = "${EXPECTED_BREW_PREFIX}" ] \
                        || { /usr/bin/printf '%s\n' 'setup:homebrew-prefix-unsupported' >&2; exit 1; }
                fi
                /usr/bin/touch "${HOMEBREW_INSTALLER}"
                /bin/chmod 0600 "${HOMEBREW_INSTALLER}"
                /usr/bin/curl --fail --location --silent --show-error "${HOMEBREW_INSTALLER_URL}" > "${HOMEBREW_INSTALLER}"
                actual_installer_hash="$(/usr/bin/shasum -a 256 "${HOMEBREW_INSTALLER}" | /usr/bin/awk '{print $1}')"
                [ "${actual_installer_hash}" = "${HOMEBREW_INSTALLER_SHA256}" ] \
                    || { /usr/bin/printf '%s\n' 'setup:homebrew-integrity-failed' >&2; exit 1; }
                HOMEBREW_INSTALLED_THIS_ATTEMPT=1
                /bin/bash "${HOMEBREW_INSTALLER}"
            fi
            BREW="${EXPECTED_BREW_PREFIX}/bin/brew"
            [ -x "${BREW}" ] || { /usr/bin/printf '%s\n' 'setup:homebrew-missing' >&2; exit 1; }
            BREW_PREFIX="$("${BREW}" --prefix)"
            [ "${BREW_PREFIX}" = "${EXPECTED_BREW_PREFIX}" ] \
                || { /usr/bin/printf '%s\n' 'setup:homebrew-prefix-unsupported' >&2; exit 1; }
            for formula in caddy dnsmasq php composer git openssl@3; do
                "${BREW}" list --formula "${formula}" >/dev/null 2>&1 || "${BREW}" install "${formula}"
            done
            [ -x "${BREW_PREFIX}/opt/openssl@3/bin/openssl" ] \
                || { /usr/bin/printf '%s\n' 'setup:openssl-missing' >&2; exit 1; }

            enable_remote_login
            if [ "${REMOTE_LOGIN_WAS_ENABLED}" -eq 0 ]; then
                /usr/bin/sudo /usr/sbin/systemsetup -setremotelogin on >/dev/null
                REMOTE_LOGIN_CHANGED=1
            fi

            install_pf
            PF_ANCHOR_CANDIDATE="${WORK_DIRECTORY}/pf-anchor"
            PF_CONFIG_CANDIDATE="${WORK_DIRECTORY}/pf.conf"
            /bin/cat > "${PF_ANCHOR_CANDIDATE}" <<EOF
            # Orbit app-dev managed PF anchor
            rdr pass inet proto tcp from any to ${WIREGUARD_ADDRESS} port 80 -> ${WIREGUARD_ADDRESS} port 8080
            rdr pass inet proto tcp from any to ${WIREGUARD_ADDRESS} port 443 -> ${WIREGUARD_ADDRESS} port 8443
            EOF
            /usr/bin/awk '
                /^# BEGIN ORBIT APP-DEV$/ { skipping = 1; next }
                /^# END ORBIT APP-DEV$/ { skipping = 0; next }
                skipping != 1 { print }
            ' "${PF_CONFIG}" > "${PF_CONFIG_CANDIDATE}"
            /usr/bin/printf '%s\n' \
                '# BEGIN ORBIT APP-DEV' \
                'rdr-anchor "com.orbit.app-dev"' \
                'load anchor "com.orbit.app-dev" from "/etc/pf.anchors/com.orbit.app-dev"' \
                '# END ORBIT APP-DEV' >> "${PF_CONFIG_CANDIDATE}"
            /usr/bin/sudo /sbin/pfctl -vnf "${PF_ANCHOR_CANDIDATE}" >/dev/null
            /usr/bin/sudo /sbin/pfctl -vnf "${PF_CONFIG_CANDIDATE}" >/dev/null
            /usr/bin/sudo /usr/bin/install -o root -g wheel -m 0644 "${PF_ANCHOR_CANDIDATE}" "${PF_ANCHOR}"
            /usr/bin/sudo /usr/bin/install -o root -g wheel -m 0644 "${PF_CONFIG_CANDIDATE}" "${PF_CONFIG}"
            /usr/bin/sudo /sbin/pfctl -f "${PF_CONFIG}" >/dev/null
            /usr/bin/sudo /sbin/pfctl -e >/dev/null 2>&1 || :
            enabled_pf_status="$(/usr/bin/sudo /sbin/pfctl -s info 2>/dev/null)" \
                || { /usr/bin/printf '%s\n' 'setup:pf-state-unavailable' >&2; exit 1; }
            /usr/bin/printf '%s\n' "${enabled_pf_status}" \
                | /usr/bin/grep -Eq '^[[:space:]]*Status: Enabled[[:space:]]*$' \
                || { /usr/bin/printf '%s\n' 'setup:pf-state-unavailable' >&2; exit 1; }

            install_dnsmasq
            DNSMASQ_CONFIG_CANDIDATE="${WORK_DIRECTORY}/dnsmasq.conf"
            DNSMASQ_PLIST_CANDIDATE="${WORK_DIRECTORY}/com.orbit.dnsmasq.plist"
            /bin/cat > "${DNSMASQ_CONFIG_CANDIDATE}" <<EOF
            port=53
            listen-address=127.0.0.1
            bind-interfaces
            no-resolv
            no-hosts
            address=/${NODE_TLD}/${WIREGUARD_ADDRESS}
            EOF
            /bin/cat > "${DNSMASQ_PLIST_CANDIDATE}" <<EOF
            <?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
            <plist version="1.0"><dict>
            <key>Label</key><string>com.orbit.dnsmasq</string>
            <key>ProgramArguments</key><array>
            <string>${BREW_PREFIX}/opt/dnsmasq/sbin/dnsmasq</string>
            <string>--keep-in-foreground</string>
            <string>--conf-file=${DNSMASQ_CONFIG}</string>
            </array>
            <key>RunAtLoad</key><true/>
            <key>KeepAlive</key><true/>
            </dict></plist>
            EOF
            /usr/bin/plutil -lint "${DNSMASQ_PLIST_CANDIDATE}" >/dev/null
            /usr/bin/sudo /bin/mkdir -p "${DNSMASQ_DIRECTORY}"
            /usr/bin/sudo /usr/bin/install -o root -g wheel -m 0644 "${DNSMASQ_CONFIG_CANDIDATE}" "${DNSMASQ_CONFIG}"
            /usr/bin/sudo /usr/bin/install -o root -g wheel -m 0644 "${DNSMASQ_PLIST_CANDIDATE}" "${DNSMASQ_PLIST}"
            /usr/bin/sudo /bin/launchctl bootout system/com.orbit.dnsmasq >/dev/null 2>&1 || true
            /usr/bin/sudo /bin/launchctl bootstrap system "${DNSMASQ_PLIST}"
            /usr/bin/sudo /bin/launchctl kickstart -k system/com.orbit.dnsmasq

            install_resolver
            RESOLVER_CANDIDATE="${WORK_DIRECTORY}/resolver"
            /usr/bin/printf '%s\n' 'nameserver 127.0.0.1' > "${RESOLVER_CANDIDATE}"
            /usr/bin/sudo /bin/mkdir -p /etc/resolver
            /usr/bin/sudo /usr/bin/install -o root -g wheel -m 0644 "${RESOLVER_CANDIDATE}" "${RESOLVER_PATH}"

            install_user_state
            /bin/mkdir -p \
                "${ORBIT_HOME}/caddy" \
                "${ORBIT_HOME}/certificates" \
                "${ORBIT_HOME}/generated" \
                "${ORBIT_HOME}/logs" \
                "${ORBIT_HOME}/php" \
                "${ORBIT_HOME}/run/php" \
                "${ORBIT_HOME}/worktrees" \
                "${EXPECTED_HOME}/apps" \
                "${EXPECTED_HOME}/.ssh" \
                "${EXPECTED_HOME}/Library/LaunchAgents"
            /bin/chmod 0700 "${EXPECTED_HOME}/.ssh"
            snapshot_user_file 'authorized-keys' "${AUTHORIZED_KEYS}"
            AUTHORIZED_KEYS_SNAPSHOTTED=1
            AUTHORIZED_KEYS_CANDIDATE="${WORK_DIRECTORY}/authorized_keys"
            if [ -f "${AUTHORIZED_KEYS}" ]; then
                /usr/bin/awk -v entry="${RESTRICTED_GATEWAY_KEY}" '
                    BEGIN {
                        count = split(entry, expected, " ")
                        key_type = expected[count - 1]
                        key_value = expected[count]
                        if (count > 2 && expected[count] !~ /^[A-Za-z0-9+\/=]+$/) {
                            key_type = expected[count - 2]
                            key_value = expected[count - 1]
                        }
                    }
                    {
                        managed = 0
                        for (field = 1; field < NF; field++) {
                            if ($field == key_type && $(field + 1) == key_value) {
                                managed = 1
                            }
                        }
                        if (managed == 0) print
                    }
                ' "${AUTHORIZED_KEYS}" > "${AUTHORIZED_KEYS_CANDIDATE}"
            else
                : > "${AUTHORIZED_KEYS_CANDIDATE}"
            fi
            /usr/bin/printf '%s\n' "${RESTRICTED_GATEWAY_KEY}" >> "${AUTHORIZED_KEYS_CANDIDATE}"
            /bin/chmod 0600 "${AUTHORIZED_KEYS_CANDIDATE}"
            /bin/mv "${AUTHORIZED_KEYS_CANDIDATE}" "${AUTHORIZED_KEYS}"
            /bin/chmod 0600 "${AUTHORIZED_KEYS}"

            CADDY_CONFIG="${ORBIT_HOME}/caddy/Caddyfile"
            /bin/cat > "${CADDY_CONFIG}" <<EOF
            {
                admin off
                auto_https off
                servers {
                    protocols h1 h2
                }
            }
            http://${WIREGUARD_ADDRESS}:8080, http://${WIREGUARD_ADDRESS}:8443 {
                respond 404
            }
            EOF
            snapshot_user_file 'caddy-plist' "${CADDY_PLIST}"
            CADDY_SNAPSHOTTED=1
            if caddy_launchctl_state="$(/bin/launchctl print "gui/${USER_ID}/com.orbit.caddy" 2>&1)"; then
                launchctl_recognized_state "${caddy_launchctl_state}" \
                    || { /usr/bin/printf '%s\n' 'setup:launchctl-state-unavailable' >&2; exit 1; }
                CADDY_WAS_LOADED=1
            elif ! launchctl_native_absence "${caddy_launchctl_state}" "gui/${USER_ID}/com.orbit.caddy"; then
                /usr/bin/printf '%s\n' 'setup:launchctl-state-unavailable' >&2
                exit 1
            fi
            /bin/cat > "${CADDY_PLIST}" <<EOF
            <?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
            <plist version="1.0"><dict>
            <key>Label</key><string>com.orbit.caddy</string>
            <key>ProgramArguments</key><array>
            <string>${BREW_PREFIX}/opt/caddy/bin/caddy</string><string>run</string>
            <string>--config</string><string>${CADDY_CONFIG}</string><string>--adapter</string><string>caddyfile</string>
            </array>
            <key>EnvironmentVariables</key><dict><key>HOME</key><string>${EXPECTED_HOME}</string></dict>
            <key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
            <key>StandardOutPath</key><string>${ORBIT_HOME}/logs/caddy.log</string>
            <key>StandardErrorPath</key><string>${ORBIT_HOME}/logs/caddy-error.log</string>
            </dict></plist>
            EOF
            /usr/bin/plutil -lint "${CADDY_PLIST}" >/dev/null
            "${BREW_PREFIX}/opt/caddy/bin/caddy" validate --config "${CADDY_CONFIG}" --adapter caddyfile
            /bin/launchctl bootout "gui/${USER_ID}" "${CADDY_PLIST}" >/dev/null 2>&1 || true
            /bin/launchctl bootstrap "gui/${USER_ID}" "${CADDY_PLIST}"
            /bin/launchctl enable "gui/${USER_ID}/com.orbit.caddy"
            /bin/launchctl kickstart -k "gui/${USER_ID}/com.orbit.caddy"

            PHP_FORMULAE="$("${BREW}" list --formula | /usr/bin/awk '/^php(@[0-9]+\.[0-9]+)?$/ { print }')"
            [ -n "${PHP_FORMULAE}" ] || { /usr/bin/printf '%s\n' 'setup:php-missing' >&2; exit 1; }
            for php_formula in ${PHP_FORMULAE}; do
                php_prefix="${BREW_PREFIX}/opt/${php_formula}"
                php_version="$("${php_prefix}/bin/php-config" --version | /usr/bin/awk -F. '{ print $1 "." $2 }')"
                [ -n "${php_version}" ] || { /usr/bin/printf '%s\n' 'setup:php-version-invalid' >&2; exit 1; }
                php_directory="${ORBIT_HOME}/php/${php_version}"
                php_config="${php_directory}/php-fpm.conf"
                php_socket="${ORBIT_HOME}/run/php/health-${php_version}.sock"
                php_label="com.orbit.php-fpm.${php_version}"
                php_plist="${EXPECTED_HOME}/Library/LaunchAgents/${php_label}.plist"
                php_backup="php-plist-${php_version}"
                /bin/mkdir -p "${php_directory}"
                snapshot_user_file "${php_backup}" "${php_plist}"
                /usr/bin/printf '%s|%s|%s\n' "${php_backup}" "${php_plist}" "${php_label}" >> "${PHP_AGENT_RECORDS}"
                if php_launchctl_state="$(/bin/launchctl print "gui/${USER_ID}/${php_label}" 2>&1)"; then
                    launchctl_recognized_state "${php_launchctl_state}" \
                        || { /usr/bin/printf '%s\n' 'setup:launchctl-state-unavailable' >&2; exit 1; }
                    /usr/bin/printf '%s\n' "${php_label}" >> "${PHP_AGENTS_LOADED}"
                elif ! launchctl_native_absence "${php_launchctl_state}" "gui/${USER_ID}/${php_label}"; then
                    /usr/bin/printf '%s\n' 'setup:launchctl-state-unavailable' >&2
                    exit 1
                fi
                /bin/cat > "${php_config}" <<EOF
            [global]
            pid = ${ORBIT_HOME}/run/php/php-fpm-${php_version}.pid
            error_log = ${ORBIT_HOME}/logs/php-fpm-${php_version}.log
            daemonize = no
            [orbit-health]
            listen = ${php_socket}
            pm = ondemand
            pm.max_children = 2
            catch_workers_output = yes
            EOF
                /bin/cat > "${php_plist}" <<EOF
            <?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
            <plist version="1.0"><dict>
            <key>Label</key><string>${php_label}</string>
            <key>ProgramArguments</key><array>
            <string>${php_prefix}/sbin/php-fpm</string><string>--nodaemonize</string><string>--fpm-config</string><string>${php_config}</string>
            </array>
            <key>EnvironmentVariables</key><dict><key>HOME</key><string>${EXPECTED_HOME}</string></dict>
            <key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
            <key>StandardOutPath</key><string>${ORBIT_HOME}/logs/php-fpm-${php_version}.log</string>
            <key>StandardErrorPath</key><string>${ORBIT_HOME}/logs/php-fpm-${php_version}-error.log</string>
            </dict></plist>
            EOF
                /usr/bin/plutil -lint "${php_plist}" >/dev/null
                "${php_prefix}/sbin/php-fpm" --test --fpm-config "${php_config}"
                /bin/launchctl bootout "gui/${USER_ID}" "${php_plist}" >/dev/null 2>&1 || true
                /bin/launchctl bootstrap "gui/${USER_ID}" "${php_plist}"
                /bin/launchctl enable "gui/${USER_ID}/${php_label}"
                /bin/launchctl kickstart -k "gui/${USER_ID}/${php_label}"
            done

            verify_local_state
            /usr/bin/sudo /sbin/pfctl -a com.orbit.app-dev -sr >/dev/null
            /usr/bin/sudo /bin/launchctl print system/com.orbit.dnsmasq >/dev/null
            /usr/bin/sudo /usr/bin/cmp -s "${RESOLVER_PATH}" "${RESOLVER_CANDIDATE}"
            /bin/launchctl print "gui/${USER_ID}/com.orbit.caddy" >/dev/null
            for php_formula in ${PHP_FORMULAE}; do
                php_prefix="${BREW_PREFIX}/opt/${php_formula}"
                php_version="$("${php_prefix}/bin/php-config" --version | /usr/bin/awk -F. '{ print $1 "." $2 }')"
                /bin/launchctl print "gui/${USER_ID}/com.orbit.php-fpm.${php_version}" >/dev/null
            done
            "${BREW_PREFIX}/opt/openssl@3/bin/openssl" version >/dev/null

            SETUP_SUCCEEDED=1
            /usr/bin/printf '%s\n' 'setup:complete'
            BASH;
    }
}
