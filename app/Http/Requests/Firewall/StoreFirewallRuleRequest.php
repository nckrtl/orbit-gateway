<?php

declare(strict_types=1);

namespace App\Http\Requests\Firewall;

use App\Data\Firewall\StoreFirewallRuleData;
use App\Domain\Firewall\FirewallAction;
use App\Domain\Firewall\FirewallPort;
use App\Domain\Firewall\FirewallSource;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;
use Illuminate\Validation\Validator;
use InvalidArgumentException;

final class StoreFirewallRuleRequest extends FormRequest
{
    /** @return array<string, list<mixed>> */
    public function rules(): array
    {
        return [
            'name' => [
                'required',
                'string',
                'max:63',
                'regex:/\A[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?\z/D',
            ],
            'source' => ['sometimes', 'string', 'max:255'],
            'protocol' => ['sometimes', Rule::in(['tcp', 'udp'])],
            'port' => ['required', 'string', 'max:11'],
        ];
    }

    /** @return list<callable(Validator): void> */
    public function after(): array
    {
        return [
            function (Validator $validator): void {
                $this->validateSource($validator);
                $this->validatePort($validator);
            },
        ];
    }

    public function getData(): StoreFirewallRuleData
    {
        /** @var array{name: string, source?: string, protocol?: string, port: string} $validated */
        $validated = $this->validated();
        $routeAction = $this->route('firewall_action');

        return new StoreFirewallRuleData(
            name: $validated['name'],
            action: FirewallAction::from(is_string($routeAction) ? $routeAction : ''),
            source: FirewallSource::normalize($validated['source'] ?? 'any'),
            protocol: $validated['protocol'] ?? 'tcp',
            port: FirewallPort::normalize($validated['port']),
        );
    }

    /** @mago-expect analysis:mixed-assignment Request input is an untyped boundary. */
    private function validateSource(Validator $validator): void
    {
        $source = $this->input('source', 'any');

        if (! is_string($source)) {
            return;
        }

        try {
            FirewallSource::normalize($source);
        } catch (InvalidArgumentException) {
            $validator->errors()->add('source', 'The source must be any or a valid IPv4 or IPv6 CIDR.');
        }
    }

    /** @mago-expect analysis:mixed-assignment Request input is an untyped boundary. */
    private function validatePort(Validator $validator): void
    {
        $port = $this->input('port');

        if (! is_string($port)) {
            return;
        }

        try {
            FirewallPort::normalize($port);
        } catch (InvalidArgumentException) {
            $validator->errors()->add('port', 'The port must be from 1 to 65535 or an ordered bounded range.');
        }
    }
}
