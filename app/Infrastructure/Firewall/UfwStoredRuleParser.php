<?php

declare(strict_types=1);

namespace App\Infrastructure\Firewall;

use App\Domain\Firewall\FirewallPort;
use App\Domain\Firewall\FirewallSource;
use InvalidArgumentException;

/**
 * @mago-expect lint:cyclomatic-complexity Stored UFW parsing rejects every unsupported managed tuple.
 * @mago-expect lint:kan-defect The score reflects fail-closed tuple parsing and ownership branches.
 */
final readonly class UfwStoredRuleParser
{
    public function __construct(
        private UfwRuleOwnershipResolver $ownership = new UfwRuleOwnershipResolver,
    ) {}

    public function ownership(string $output, UfwRuleShape $expected): UfwRuleOwnership
    {
        $matchingLines = $this->matchingCommentLineCount($output, $expected->comment);
        $observed = $this->ruleShapes($output, $expected->comment);

        return $this->ownership->resolve($matchingLines, $observed, $expected);
    }

    /** @return list<UfwRuleShape> */
    private function ruleShapes(string $output, string $comment): array
    {
        $rules = [];

        foreach (explode("\n", $output) as $line) {
            $rule = $this->parseLine($line, $comment);

            if ($rule !== null) {
                $rules[] = $rule;
            }
        }

        return $rules;
    }

    private function matchingCommentLineCount(string $output, string $comment): int
    {
        $matches = 0;

        foreach (explode("\n", $output) as $line) {
            $observed = $this->comment($line);

            if ($observed !== null && hash_equals($comment, $observed)) {
                $matches++;
            }
        }

        return $matches;
    }

    private function comment(string $line): ?string
    {
        $matches = [];

        if (preg_match('/\scomment=([0-9a-fA-F]+)\s*\z/D', trim($line), $matches) !== 1) {
            return null;
        }

        $decoded = hex2bin($matches[1]);

        return is_string($decoded) ? $decoded : null;
    }

    private function parseLine(string $line, string $comment): ?UfwRuleShape
    {
        $matches = [];

        if (
            preg_match(
                '/\A__orbit_ufw_tuple:(v4|v6):### tuple ### (.+) comment=([0-9a-fA-F]+)\z/D',
                trim($line),
                $matches,
            ) !== 1
        ) {
            return null;
        }

        $decodedComment = hex2bin($matches[3]);

        if (! is_string($decodedComment) || ! hash_equals($comment, $decodedComment)) {
            return null;
        }

        $tokens = preg_split('/\s+/', trim($matches[2]));

        if (! is_array($tokens) || count($tokens) !== 7 || $tokens[4] !== 'any') {
            return null;
        }

        [$actionToken, $protocol, $port, $destination, , $source, $interfaces] = $tokens;
        $forward = str_starts_with($actionToken, 'route:');
        $action = $forward ? substr($actionToken, strlen('route:')) : $actionToken;
        $interfaceShape = $forward
            ? $this->forwardInterfaces($interfaces)
            : $this->directionalInterfaces($interfaces);

        if (! in_array(needle: $action, haystack: ['allow', 'deny'], strict: true) || $interfaceShape === null) {
            return null;
        }

        if (! in_array(needle: $protocol, haystack: ['any', 'tcp', 'udp'], strict: true)) {
            return null;
        }

        try {
            $normalizedPort = $port === 'any' ? 'any' : FirewallPort::normalize($port);
            $normalizedSource = $this->normalizeEndpoint($source);
            $normalizedDestination = $this->normalizeEndpoint($destination);
        } catch (InvalidArgumentException) {
            return null;
        }

        $family = $matches[1];

        if (
            ! $this->endpointMatchesFamily($normalizedSource, $family)
            || ! $this->endpointMatchesFamily($normalizedDestination, $family)
        ) {
            return null;
        }

        return new UfwRuleShape(
            comment: $comment,
            action: $action,
            direction: $interfaceShape['direction'],
            source: $normalizedSource,
            destination: $normalizedDestination,
            port: $normalizedPort,
            protocol: $protocol,
            inInterface: $interfaceShape['in'],
            outInterface: $interfaceShape['out'],
            family: $family,
        );
    }

    /** @return array{direction: string, in: string, out: string}|null */
    private function forwardInterfaces(string $value): ?array
    {
        $matches = [];

        if (preg_match('/\Ain_([a-zA-Z0-9_.:-]+)!out_([a-zA-Z0-9_.:-]+)\z/D', $value, $matches) !== 1) {
            return null;
        }

        return ['direction' => 'fwd', 'in' => $matches[1], 'out' => $matches[2]];
    }

    /** @return array{direction: string, in: ?string, out: ?string}|null */
    private function directionalInterfaces(string $value): ?array
    {
        if ($value === 'in') {
            return ['direction' => 'in', 'in' => null, 'out' => null];
        }

        if ($value === 'out') {
            return ['direction' => 'out', 'in' => null, 'out' => null];
        }

        $matches = [];

        if (preg_match('/\A(in|out)_([a-zA-Z0-9_.:-]+)\z/D', $value, $matches) !== 1) {
            return null;
        }

        return (
            $matches[1] === 'in'
                ? ['direction' => 'in', 'in' => $matches[2], 'out' => null]
                : ['direction' => 'out', 'in' => null, 'out' => $matches[2]]
        );
    }

    private function normalizeEndpoint(string $value): string
    {
        return FirewallSource::normalize(match ($value) {
            'Anywhere', '0.0.0.0/0', '::/0' => 'any',
            default => trim($value),
        });
    }

    private function endpointMatchesFamily(string $endpoint, string $family): bool
    {
        $endpointFamily = FirewallSource::family($endpoint);

        return $endpointFamily === 'both' || $endpointFamily === $family;
    }
}
