<?php

declare(strict_types=1);

namespace App\Providers;

use Illuminate\Support\Collection;
use Laravel\Boost\Install\GuidelineComposer;
use Laravel\Boost\Rules\RuleFrontmatter;
use RuntimeException;

/**
 * @mago-expect lint:cyclomatic-complexity Project guidance validation keeps every fail-closed index gate together.
 * @mago-expect lint:kan-defect Each branch rejects one incomplete or unsafe rule-set shape.
 */
final class GatewayGuidelineComposer extends GuidelineComposer
{
    /** @var list<string> */
    private const array REQUIRED_RULE_FILES = [
        '.ai/rules/app.md',
        '.ai/rules/boost/http-routes.md',
        '.ai/rules/boost/models.md',
        '.ai/rules/boost/tests.md',
        '.ai/rules/infrastructure.md',
        '.ai/rules/tests.md',
    ];

    /** @return Collection<string, array> */
    public function resolvedGuidelines(): Collection
    {
        $this->assertRequiredProjectRulesAreReadable();

        return parent::resolvedGuidelines();
    }

    public function compose(): string
    {
        $guidelines = parent::compose();
        $optionalLocation = 'in `.ai/rules` when that directory exists';
        $permissiveFallback = 'If `.ai/rules` does not exist, continue without it.';

        if (
            substr_count($guidelines, $optionalLocation) !== 1
            || substr_count($guidelines, $permissiveFallback) !== 1
        ) {
            throw new RuntimeException(
                'Boost project-rule guidance changed. Update the Gateway hard-stop transformation before regenerating.',
            );
        }

        return str_replace(
            [
                $optionalLocation,
                $permissiveFallback,
            ],
            [
                'in `.ai/rules` as required repository state',
                '`.ai/rules/index.md` and every rule file indexed by it are required repository state. '
                    .'If the index or any indexed rule file is missing or unreadable, the checkout or Boost bootstrap '
                    .'is incomplete. Read every indexed rule whose globs match the files in scope before planning or '
                    .'editing. Stop and restore or regenerate the guidance before continuing.',
            ],
            $guidelines,
        );
    }

    private function assertRequiredProjectRulesAreReadable(): void
    {
        $indexRelativePath = '.ai/rules/index.md';
        $indexPath = base_path($indexRelativePath);

        if (! is_file($indexPath) || ! is_readable($indexPath)) {
            throw new RuntimeException(
                "Required project rule index is missing or unreadable: {$indexRelativePath}.",
            );
        }

        $rulesDirectory = base_path('.ai/rules');
        $resolvedBasePath = realpath(base_path());
        $resolvedRulesDirectory = realpath($rulesDirectory);

        if (
            ! is_string($resolvedBasePath)
            || ! is_string($resolvedRulesDirectory)
            || is_link($rulesDirectory)
            || ! str_starts_with($resolvedRulesDirectory, $resolvedBasePath.DIRECTORY_SEPARATOR)
        ) {
            throw new RuntimeException(
                'Required project rules directory resolves outside the checkout: .ai/rules.',
            );
        }

        $resolvedIndexPath = realpath($indexPath);

        if (
            ! is_string($resolvedIndexPath)
            || is_link($indexPath)
            || dirname($resolvedIndexPath) !== $resolvedRulesDirectory
        ) {
            throw new RuntimeException(
                "Required project rule index resolves outside the checkout: {$indexRelativePath}.",
            );
        }

        $index = file_get_contents($indexPath);

        if (! is_string($index)) {
            throw new RuntimeException(
                "Required project rule index is missing or unreadable: {$indexRelativePath}.",
            );
        }

        $indexedRules = $this->indexedRules($index, $indexRelativePath);
        $indexedRuleFiles = array_keys($indexedRules);
        $sortedIndexedRuleFiles = $indexedRuleFiles;
        $sortedRequiredRuleFiles = self::REQUIRED_RULE_FILES;
        sort($sortedIndexedRuleFiles);
        sort($sortedRequiredRuleFiles);

        if ($sortedIndexedRuleFiles !== $sortedRequiredRuleFiles) {
            throw new RuntimeException(
                'Required project rule index does not match the complete project rule inventory.',
            );
        }

        foreach ($indexedRules as $indexedRuleFile => $indexedGlobs) {
            $rulePath = base_path($indexedRuleFile);

            if (! is_file($rulePath) || ! is_readable($rulePath)) {
                throw new RuntimeException(
                    "Required indexed project rule is missing or unreadable: {$indexedRuleFile}.",
                );
            }

            $resolvedRulePath = realpath($rulePath);

            if (
                ! is_string($resolvedRulePath)
                || is_link($rulePath)
                || ! str_starts_with($resolvedRulePath, $resolvedRulesDirectory.DIRECTORY_SEPARATOR)
            ) {
                throw new RuntimeException(
                    "Required indexed project rule resolves outside .ai/rules: {$indexedRuleFile}.",
                );
            }

            $rule = file_get_contents($rulePath);

            if (! is_string($rule)) {
                throw new RuntimeException(
                    "Required indexed project rule is missing or unreadable: {$indexedRuleFile}.",
                );
            }

            if (RuleFrontmatter::parse($rule)['paths'] !== $indexedGlobs) {
                throw new RuntimeException(
                    "Indexed project rule frontmatter does not match the index: {$indexedRuleFile}.",
                );
            }
        }
    }

    /** @return array<string, list<string>> */
    private function indexedRules(string $index, string $indexRelativePath): array
    {
        $lines = preg_split('/\R/', $index);
        $indexedRules = [];

        if (! is_array($lines)) {
            throw new RuntimeException('Required project rule index contains an invalid rule row.');
        }

        foreach ($lines as $line) {
            $line = trim($line);

            if (! str_starts_with($line, '|')) {
                continue;
            }

            $columns = array_map(
                trim(...),
                explode('|', trim(string: $line, characters: " \t|")),
            );

            if (
                count($columns) === 2
                && $columns[0] === 'Applies to'
                && $columns[1] === 'Rule file'
            ) {
                continue;
            }

            if ($this->isTableSeparator($columns)) {
                continue;
            }

            if (count($columns) !== 2 || $columns[0] === '' || $columns[1] === '') {
                throw new RuntimeException('Required project rule index contains an invalid rule row.');
            }

            [$globs, $ruleFile] = $columns;

            if (! str_starts_with($ruleFile, '.ai/rules/') || ! str_ends_with($ruleFile, '.md')) {
                throw new RuntimeException('Required project rule index contains an invalid rule row.');
            }

            if (! $this->isSafeRulePath($ruleFile)) {
                throw new RuntimeException(
                    "Required project rule index contains an unsafe rule path: {$ruleFile}.",
                );
            }

            $indexedGlobs = array_map(trim(...), explode(',', $globs));

            if (
                in_array(needle: '', haystack: $indexedGlobs, strict: true)
                || array_key_exists(key: $ruleFile, array: $indexedRules)
            ) {
                throw new RuntimeException('Required project rule index contains an invalid rule row.');
            }

            $indexedRules[$ruleFile] = $indexedGlobs;
        }

        if ($indexedRules === []) {
            throw new RuntimeException(
                "Required project rule index contains no project rules: {$indexRelativePath}.",
            );
        }

        return $indexedRules;
    }

    /** @param list<string> $columns */
    private function isTableSeparator(array $columns): bool
    {
        return (
            count($columns) === 2
            && preg_match('/\A:?-{3,}:?\z/', $columns[0]) === 1
            && preg_match('/\A:?-{3,}:?\z/', $columns[1]) === 1
        );
    }

    private function isSafeRulePath(string $ruleFile): bool
    {
        $relativeRuleFile = substr($ruleFile, strlen('.ai/rules/'));
        $segments = explode('/', $relativeRuleFile);

        return array_all(
            $segments,
            static fn (string $segment): bool => ! (
                $segment === ''
                || $segment === '.'
                || $segment === '..'
                || preg_match('/\A[a-zA-Z0-9._-]+\z/', $segment) !== 1
            ),
        );
    }
}
