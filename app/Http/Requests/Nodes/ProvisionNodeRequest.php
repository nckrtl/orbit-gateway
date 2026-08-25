<?php

declare(strict_types=1);

namespace App\Http\Requests\Nodes;

use App\Data\Nodes\ProvisionNodeData;
use App\Domain\Nodes\RoleName;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;

final class ProvisionNodeRequest extends FormRequest
{
    /** @return array<string, list<mixed>> */
    public function rules(): array
    {
        return [
            'name' => ['required', 'string', 'alpha_dash:ascii', 'max:63'],
            'public_ssh_host' => ['required', 'string', 'max:255'],
            'public_ssh_port' => ['sometimes', 'integer', 'between:1,65535'],
            'ssh_user' => ['sometimes', 'string', 'max:32'],
            'roles' => ['sometimes', 'array'],
            'roles.*' => ['required', Rule::enum(RoleName::class)],
            'wireguard_address' => ['nullable', 'ipv4'],
            'wireguard_endpoint_override' => ['nullable', 'string', 'max:255'],
            'dns_server_override' => ['nullable', 'ip'],
        ];
    }

    /** @mago-expect analysis:mixed-assignment Validated request data starts at an untyped boundary. */
    public function payload(): ProvisionNodeData
    {
        $validated = $this->validated();
        $roles = is_array($validated['roles'] ?? null) ? $validated['roles'] : [];

        return new ProvisionNodeData(
            name: (string) $validated['name'],
            publicSshHost: (string) $validated['public_ssh_host'],
            roles: array_values(array_map(
                RoleName::from(...),
                $roles,
            )),
            publicSshPort: is_int($validated['public_ssh_port'] ?? null) ? $validated['public_ssh_port'] : 22,
            sshUser: is_string($validated['ssh_user'] ?? null) ? $validated['ssh_user'] : 'root',
            wireguardAddress: is_string($validated['wireguard_address'] ?? null)
                ? $validated['wireguard_address']
                : null,
            wireguardEndpointOverride: is_string($validated['wireguard_endpoint_override'] ?? null)
                ? $validated['wireguard_endpoint_override']
                : null,
            dnsServerOverride: is_string($validated['dns_server_override'] ?? null)
                ? $validated['dns_server_override']
                : null,
        );
    }
}
