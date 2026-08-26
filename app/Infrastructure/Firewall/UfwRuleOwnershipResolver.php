<?php

declare(strict_types=1);

namespace App\Infrastructure\Firewall;

final class UfwRuleOwnershipResolver
{
    /** @param list<UfwRuleShape> $observed */
    public function resolve(
        int $matchingLines,
        array $observed,
        UfwRuleShape $expected,
    ): UfwRuleOwnership {
        if ($matchingLines === 0) {
            return UfwRuleOwnership::Missing;
        }

        if (count($observed) !== $matchingLines) {
            return UfwRuleOwnership::Drift;
        }

        $families = [];

        foreach ($observed as $shape) {
            if (! $expected->matches($shape)) {
                return UfwRuleOwnership::Drift;
            }

            $family = $shape->family ?? 'unknown';

            if (array_key_exists($family, $families)) {
                return UfwRuleOwnership::Drift;
            }

            $families[$family] = true;
        }

        $expectedFamilies = $expected->family === null ? ['v4', 'v6'] : [$expected->family];
        $observedFamilies = array_keys($families);
        sort($expectedFamilies);
        sort($observedFamilies);

        return $observedFamilies === $expectedFamilies
            ? UfwRuleOwnership::Exact
            : UfwRuleOwnership::Drift;
    }
}
