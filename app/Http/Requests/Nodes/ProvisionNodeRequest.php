<?php

declare(strict_types=1);

namespace App\Http\Requests\Nodes;

use App\Data\Nodes\ProvisionNodeData;
use App\Domain\Nodes\NodeTld;
use App\Domain\Nodes\RoleName;
use App\Domain\WireGuard\WireGuardEndpoint;
use App\Models\Node;
use Closure;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;
use JsonException;

/** @mago-expect lint:cyclomatic-complexity This request keeps transport normalization and typed payload mapping at one boundary. */
final class ProvisionNodeRequest extends FormRequest
{
    protected function prepareForValidation(): void
    {
        /** @mago-expect analysis:mixed-assignment Request input is an untyped boundary. */
        $tld = $this->input('tld');

        if (! is_string($tld)) {
            return;
        }

        $this->merge(['tld' => NodeTld::normalize($tld)]);
    }

    /**
     * Preserve explicit blank peer addresses so the allocator can reject them.
     *
     * @return array<array-key, mixed>
     *
     * @mago-expect analysis:mixed-assignment Decoded JSON is an untyped transport boundary.
     */
    public function validationData(): array
    {
        $data = parent::validationData();

        if (! $this->isJson()) {
            return $data;
        }

        try {
            $payload = json_decode($this->getContent(), associative: true, flags: JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            return $data;
        }

        if (is_array($payload) && array_key_exists('wireguard_address', $payload)) {
            $data['wireguard_address'] = $payload['wireguard_address'];
        }

        return $data;
    }

    /** @return array<string, list<mixed>> */
    public function rules(): array
    {
        return [
            'name' => ['required', 'string', 'alpha_dash:ascii', 'max:63'],
            'public_ssh_host' => [
                Rule::requiredIf($this->requiresPublicSshHost(...)),
                'string',
                'max:255',
            ],
            'platform' => ['sometimes', 'string', Rule::in(['linux', 'darwin'])],
            'architecture' => ['nullable', 'string', 'regex:/\A[A-Za-z0-9_.-]{1,64}\z/D'],
            'tld' => [
                'nullable',
                'string',
                'max:253',
                'regex:/\A[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\z/D',
            ],
            'public_ssh_port' => ['sometimes', 'integer', 'between:1,65535'],
            'ssh_user' => ['sometimes', 'string', 'max:32'],
            'roles' => ['sometimes', 'array'],
            'roles.*' => ['required', Rule::enum(RoleName::class)],
            // The allocator owns format, family, subnet, and uniqueness errors.
            'wireguard_address' => ['nullable'],
            'wireguard_endpoint_override' => [
                'nullable',
                'string',
                'max:255',
                static function (string $attribute, mixed $value, Closure $fail): void {
                    if (! is_string($value) || ! WireGuardEndpoint::isValid($value)) {
                        $fail("The {$attribute} field must be a valid WireGuard endpoint.");
                    }
                },
            ],
            'dns_server_override' => ['nullable', 'ip'],
            'host_key_fingerprint' => [
                'nullable',
                'string',
                'regex:#\ASHA256:[A-Za-z0-9+/]{43}\z#D',
            ],
        ];
    }

    /** @return array<string, string> */
    public function messages(): array
    {
        return [
            'public_ssh_host.required' => 'The public SSH host field is required for a new Linux node.',
        ];
    }

    /** @mago-expect analysis:mixed-assignment Validated request data starts at an untyped boundary. */
    public function payload(): ProvisionNodeData
    {
        $validated = $this->validated();
        $roles = is_array($validated['roles'] ?? null) ? $validated['roles'] : [];

        return new ProvisionNodeData(
            name: (string) $validated['name'],
            publicSshHost: is_string($validated['public_ssh_host'] ?? null) ? $validated['public_ssh_host'] : '',
            roles: array_values(array_map(
                RoleName::from(...),
                $roles,
            )),
            publicSshPort: is_int($validated['public_ssh_port'] ?? null) ? $validated['public_ssh_port'] : 22,
            sshUser: is_string($validated['ssh_user'] ?? null) ? $validated['ssh_user'] : 'root',
            wireguardAddress: $this->wireguardAddress($validated),
            wireguardEndpointOverride: is_string($validated['wireguard_endpoint_override'] ?? null)
                ? $validated['wireguard_endpoint_override']
                : null,
            dnsServerOverride: is_string($validated['dns_server_override'] ?? null)
                ? $validated['dns_server_override']
                : null,
            expectedSshHostFingerprint: is_string($validated['host_key_fingerprint'] ?? null)
                ? $validated['host_key_fingerprint']
                : null,
            platform: is_string($validated['platform'] ?? null) ? $validated['platform'] : 'linux',
            architecture: is_string($validated['architecture'] ?? null) ? $validated['architecture'] : null,
            tld: is_string($validated['tld'] ?? null) ? $validated['tld'] : null,
        );
    }

    /** @param array<array-key, mixed> $validated */
    private function wireguardAddress(array $validated): ?string
    {
        if (! array_key_exists('wireguard_address', $validated) || $validated['wireguard_address'] === null) {
            return null;
        }

        return is_string($validated['wireguard_address']) ? $validated['wireguard_address'] : '';
    }

    private function requiresPublicSshHost(): bool
    {
        if ($this->input('platform') === 'darwin') {
            return false;
        }

        /** @mago-expect analysis:mixed-assignment Request input is an untyped boundary. */
        $name = $this->input('name');

        if (! is_string($name) || $name === '') {
            return true;
        }

        return ! Node::query()
            ->where('name', $name)
            ->whereNotNull('public_ssh_host')
            ->where('public_ssh_host', '!=', '')
            ->exists();
    }
}
