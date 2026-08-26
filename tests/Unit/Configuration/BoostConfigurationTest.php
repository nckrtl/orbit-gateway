<?php

declare(strict_types=1);

use Symfony\Component\Yaml\Yaml;

/** @return array{paths: list<string>, globs: list<list<string>>} */
$parseIndexedRuleRows = static function (string $index): array {
    preg_match_all(
        pattern: '/^\|\s*(?<globs>[^|]+?)\s*\|\s*(?<path>\.ai\/rules\/[^|]+\.md)\s*\|$/m',
        subject: $index,
        matches: $matches,
    );

    return [
        'paths' => array_map(trim(...), $matches['path'] ?? []),
        'globs' => array_map(
            static fn (string $globs): array => array_map(trim(...), explode(',', $globs)),
            $matches['globs'] ?? [],
        ),
    ];
};

it('enables durable rules and scoped guideline extraction', function (): void {
    /** @var array<string, mixed> $configuration */
    $configuration = require dirname(path: __DIR__, levels: 3).'/config/boost.php';

    expect($configuration['rules'] ?? null)
        ->toBe([
            'enabled' => true,
            'scoped_guidelines' => true,
        ])
        ->and($configuration['enforce_tests'] ?? null)
        ->toBeTrue();
});

it('requires the committed rule index and every indexed rule file before edits', function () use (
    $parseIndexedRuleRows,
): void {
    $projectRoot = dirname(path: __DIR__, levels: 3);
    $indexPath = "{$projectRoot}/.ai/rules/index.md";

    expect($indexPath)
        ->toBeFile()
        ->and(is_readable($indexPath))
        ->toBeTrue();

    $index = file_get_contents($indexPath);

    expect($index)->toBeString();

    $indexedRuleRows = $parseIndexedRuleRows($index);
    $expectedRuleFiles = [
        '.ai/rules/app.md',
        '.ai/rules/boost/http-routes.md',
        '.ai/rules/boost/models.md',
        '.ai/rules/boost/tests.md',
        '.ai/rules/bootstrap.md',
        '.ai/rules/database.md',
        '.ai/rules/http.md',
        '.ai/rules/infrastructure.md',
        '.ai/rules/tests.md',
    ];
    $indexedRulePaths = $indexedRuleRows['paths'];

    expect($indexedRulePaths)
        ->toBe(array_values(array_unique($indexedRulePaths)))
        ->toBe($expectedRuleFiles);

    $indexedRuleFiles = [];

    foreach ($indexedRulePaths as $entry => $indexedRulePath) {
        $indexedRuleFiles[$indexedRulePath] = $indexedRuleRows['globs'][$entry];
    }

    expect($indexedRuleFiles)->not->toBeEmpty();

    foreach ($indexedRuleFiles as $indexedRuleFile => $indexedGlobs) {
        $rulePath = "{$projectRoot}/{$indexedRuleFile}";

        expect($rulePath)
            ->toBeFile("Indexed rule file does not exist: {$indexedRuleFile}")
            ->and(is_readable($rulePath))
            ->toBeTrue("Indexed rule file is not readable: {$indexedRuleFile}");

        $rule = file_get_contents($rulePath);

        expect($rule)->toBeString();
        expect(trim($rule))->not->toBeEmpty("Indexed rule file is empty: {$indexedRuleFile}");

        preg_match('/\A---\R(?<frontmatter>.*?)\R---\R/s', $rule, $frontmatterMatch);
        $frontmatter = Yaml::parse($frontmatterMatch['frontmatter'] ?? '');

        expect($frontmatter)
            ->toBeArray()
            ->and($frontmatter['paths'] ?? null)
            ->toBe($indexedGlobs);
    }

    $rulesDirectory = "{$projectRoot}/.ai/rules";
    $ruleIterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($rulesDirectory, FilesystemIterator::SKIP_DOTS),
    );
    $ruleFiles = [];

    foreach ($ruleIterator as $ruleFile) {
        if (! $ruleFile->isFile() || $ruleFile->getExtension() !== 'md' || $ruleFile->getFilename() === 'index.md') {
            continue;
        }

        $ruleFiles[] = '.ai/rules/'
        .ltrim(
            string: str_replace(
                search: '\\',
                replace: '/',
                subject: substr($ruleFile->getPathname(), strlen($rulesDirectory)),
            ),
            characters: '/',
        );
    }

    sort($ruleFiles);
    $indexedPaths = array_keys($indexedRuleFiles);
    sort($indexedPaths);

    expect($indexedPaths)->toBe($ruleFiles);

    $agents = file_get_contents("{$projectRoot}/AGENTS.md");
    $projectGuidance = is_string($agents)
        ? strstr(haystack: $agents, needle: "\n<laravel-boost-guidelines>", before_needle: true)
        : false;

    expect($agents)
        ->toBeString()
        ->toContain(
            '## Required Guidance Bootstrap',
            'composer guidance:check',
            'composer guidance:update',
            'Make no product-code edits while this check fails.',
            'Never silently continue when',
            'the required project guidance is incomplete.',
        )
        ->not->toContain('in `.ai/rules` when that directory exists')
        ->not->toContain('If `.ai/rules` does not exist, continue without it.')
        ->not->toContain('when that directory exists')
        ->not->toContain('continue without it');
    expect($projectGuidance)
        ->toBeString()
        ->toContain(
            '## Required Guidance Bootstrap',
            'Restore only the affected tracked guidance path from the current branch.',
            'Boost cannot recreate deleted project-owned rules.',
            'Never silently continue when',
            'the required project guidance is incomplete.',
        );
});

it('keeps duplicate rule rows visible until uniqueness validation', function () use ($parseIndexedRuleRows): void {
    $index = <<<'MARKDOWN'
        | Applies to | Rule file |
        | --- | --- |
        | app/** | .ai/rules/app.md |
        | app/** | .ai/rules/app.md |
        MARKDOWN;
    $indexedRulePaths = $parseIndexedRuleRows($index)['paths'];

    expect($indexedRulePaths)
        ->toBe([
            '.ai/rules/app.md',
            '.ai/rules/app.md',
        ])
        ->not->toBe(array_values(array_unique($indexedRulePaths)));
});

it('keeps generated scoped guidance complete and de-duplicated', function (): void {
    $projectRoot = dirname(path: __DIR__, levels: 3);

    $readProjectFile = static function (string $relativePath) use ($projectRoot): string {
        $contents = file_get_contents("{$projectRoot}/{$relativePath}");

        if (! is_string($contents)) {
            throw new RuntimeException("Could not read {$relativePath}.");
        }

        return $contents;
    };

    $index = $readProjectFile('.ai/rules/index.md');

    expect($index)->toContain(
        '| app/Actions/**, app/Data/**, app/Domain/**, app/Exceptions/**, app/Infrastructure/**, app/Rules/** | .ai/rules/app.md |',
        '| app/Http/**, routes/** | .ai/rules/boost/http-routes.md |',
        '| app/Models/** | .ai/rules/boost/models.md |',
        '| tests/** | .ai/rules/boost/tests.md |',
        '| app/Console/**, app/Providers/**, bootstrap/**, config/**, AGENTS.md, boost.json, composer.json, composer.lock, .ai/**, .agents/**, .codex/** | .ai/rules/bootstrap.md |',
        '| app/Models/**, database/** | .ai/rules/database.md |',
        '| app/Http/**, routes/** | .ai/rules/http.md |',
        '| app/Infrastructure/** | .ai/rules/infrastructure.md |',
        '| tests/** | .ai/rules/tests.md |',
    );

    expect($readProjectFile('.ai/rules/boost/http-routes.md'))
        ->toContain(
            '## APIs & Eloquent Resources',
            'existing typed Spatie Data response objects',
        );
    expect($readProjectFile('.ai/rules/boost/models.md'))
        ->toContain('### Model Creation', 'Add a factory or seeder only when');
    expect($readProjectFile('.ai/rules/boost/tests.md'))
        ->toContain(
            '# Pest',
            'Faker:',
            'php artisan make:test --pest',
            'Read the `testing-best-practices` skill',
            'Do not delete tests or test files without approval.',
            '--filter=testName',
        );

    $appRules = $readProjectFile('.ai/rules/app.md');
    $bootstrapRules = $readProjectFile('.ai/rules/bootstrap.md');
    $databaseRules = $readProjectFile('.ai/rules/database.md');
    $httpRules = $readProjectFile('.ai/rules/http.md');
    $infrastructureRules = $readProjectFile('.ai/rules/infrastructure.md');
    $testRules = $readProjectFile('.ai/rules/tests.md');
    $projectRules = implode("\n", [
        $appRules,
        $bootstrapRules,
        $databaseRules,
        $httpRules,
        $infrastructureRules,
        $testRules,
    ]);
    $expectedDecisionHeadings = [
        '## Keep Gateway application boundaries explicit',
        '## Respect Linux and Darwin privilege boundaries',
        '## Treat incomplete guidance as a bootstrap failure',
        '## Preserve control-plane data',
        '## Keep the API contract authenticated and redacted',
        '## Use fixed typed argv',
        '## Keep secrets out of command arguments',
        '## Publish managed state atomically',
        '## Search the legacy Orbit project before infrastructure design',
        '## Run the Pest and Mago gates',
    ];

    foreach ($expectedDecisionHeadings as $expectedDecisionHeading) {
        expect(substr_count(haystack: $projectRules, needle: $expectedDecisionHeading))->toBe(1);
    }

    expect($appRules)->toContain(
        'pinned gateway SSH',
        'Darwin actions',
        'local macOS adapter',
        'Darwin steady-state SSH must not use sudo',
    );
    expect($bootstrapRules)
        ->toContain(
            'composer guidance:check',
            'composer guidance:update',
            'Restore the exact tracked guidance paths',
            'no product-code edits',
        );
    expect($databaseRules)
        ->toContain('SQLite', 'migration', 'preserve existing control-plane state');
    expect($httpRules)
        ->toContain(
            'active WireGuard peer',
            'node:setup:app-dev:script',
            'node:setup:app-dev:result',
            'registered Darwin WireGuard peers',
            'typed data objects',
            'stable error envelopes',
            'redact',
            'colon-delimited route names',
        );
    expect($infrastructureRules)
        ->toContain(
            'fixed, typed argv',
            'generic executor',
            'stdin',
            'mode-0600 protected files',
            'exact Orbit ownership',
            'lock first',
            'write a candidate',
            'validate it',
            'switch atomically',
            'restore the exact prior file or symlink',
            'explicit recovery path',
            '/home/nckrtl/orbit',
            'never port the retired Agent',
        )
        ->not->toContain('orbit-old');
    expect($testRules)
        ->toContain('Pest 5 TDD', 'Test Impact Analysis', 'without TIA', 'Rector', 'Mago', 'git diff --check');
});

it('preserves project and installed testing guidance', function (): void {
    $projectRoot = dirname(path: __DIR__, levels: 3);

    $readProjectFile = static function (string $relativePath) use ($projectRoot): string {
        $contents = file_get_contents("{$projectRoot}/{$relativePath}");

        if (! is_string($contents)) {
            throw new RuntimeException("Could not read {$relativePath}.");
        }

        return $contents;
    };

    expect($readProjectFile('AGENTS.md'))
        ->toContain(
            'Use Pest 5 with `describe()` and `it()`.',
            'Use Mago for formatting, linting, and analysis.',
            'Always activate the `spatie-laravel-php` skill',
            'Always activate the `spatie-version-control` skill',
            'Always activate the `spatie-security` skill',
            '## Skills Activation',
            'Test every code change by adding or updating a test.',
            'Read the `testing-best-practices` skill before writing tests.',
        );

    expect($readProjectFile('boost.json'))
        ->toContain(
            '"laravel-best-practices"',
            '"orbit-gateway-development"',
            '"testing-best-practices"',
            '"pest-testing"',
            '"spatie-laravel-php"',
            '"spatie-security"',
            '"spatie-version-control"',
        );

    expect($readProjectFile('.ai/skills/orbit-gateway-development/SKILL.md'))
        ->toBe($readProjectFile('.agents/skills/orbit-gateway-development/SKILL.md'));
    expect($readProjectFile('.ai/skills/pest-testing/SKILL.md'))
        ->toBe($readProjectFile('.agents/skills/pest-testing/SKILL.md'))
        ->toContain('Pest 5', 'Test Impact Analysis', '--no-tia')
        ->toContain(
            'This Gateway has no UI or browser-test surface. Do not invent browser, Livewire, or Inertia tests.',
        );
    expect($readProjectFile('.ai/skills/spatie-security/SKILL.md'))
        ->toBe($readProjectFile('.agents/skills/spatie-security/SKILL.md'));
    expect($readProjectFile('.ai/skills/spatie-security/references/spatie-security-guidelines.md'))
        ->toBe($readProjectFile('.agents/skills/spatie-security/references/spatie-security-guidelines.md'));

    expect($readProjectFile('.codex/config.toml'))
        ->toContain(
            '[mcp_servers.laravel-boost]',
            'command = "php"',
            'args = ["artisan", "boost:mcp"]',
        );

    /** @var array<string, mixed> $composer */
    $composer = json_decode(
        json: $readProjectFile('composer.json'),
        associative: true,
        flags: JSON_THROW_ON_ERROR,
    );

    expect($composer['scripts']['guidance:check'] ?? null)
        ->toBe(
            'vendor/bin/pest --no-tia --compact tests/Unit/Configuration/BoostConfigurationTest.php tests/Feature/Configuration/BoostGuidanceTest.php',
        )
        ->and($composer['scripts']['guidance:update'] ?? null)
        ->toBe([
            '@guidance:check',
            '@php artisan boost:update --no-discover --no-interaction',
            '@guidance:check',
        ])
        ->and($composer['scripts']['check'][0] ?? null)
        ->toBe('@guidance:check')
        ->and($composer['scripts']['post-autoload-dump'] ?? null)
        ->not->toContain('@guidance:check');

    expect($readProjectFile('.agents/skills/testing-best-practices/rules/assertions.md'))
        ->toContain('`assertModelExists($model)`');
    expect($readProjectFile('.agents/skills/testing-best-practices/rules/isolation.md'))
        ->toContain(
            '`Exceptions::fake()`',
            '`Event::fake()`',
            '`LazilyRefreshDatabase` instead of `RefreshDatabase`',
        );
    expect($readProjectFile('.agents/skills/testing-best-practices/rules/test-data.md'))
        ->toContain('named factory state', '`recycle()`', '`sequence()`');

    expect($readProjectFile('.agents/skills/orbit-gateway-development/SKILL.md'))
        ->toContain(
            'fixed argument arrays',
            'secrets out of local and remote argument arrays',
            'Require exact Orbit ownership before mutation.',
            'Linux privilege escalation',
            'Darwin',
            'search `/home/nckrtl/orbit/orbit`',
            'Pest 5 with TIA',
            'Mago format/lint/analyse',
        )
        ->not->toContain('orbit-old');
});

it('keeps two-factor authentication mandatory when the preferred integration is unavailable', function (): void {
    $projectRoot = dirname(path: __DIR__, levels: 3);
    $securityGuidance = file_get_contents(
        "{$projectRoot}/.agents/skills/spatie-security/references/spatie-security-guidelines.md",
    );

    expect($securityGuidance)
        ->toBeString()
        ->toContain(
            'Enable two-factor authentication for every service that supports it.',
            'Use 1Password for the second factor when the service supports that integration; otherwise use another supported authenticator.',
        )
        ->not->toContain('Enable two-factor authentication through 1Password when available.');
});
