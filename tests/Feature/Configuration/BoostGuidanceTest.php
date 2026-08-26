<?php

declare(strict_types=1);

use App\Console\GatewayBoostInstallCommand;
use App\Providers\GatewayGuidelineComposer;
use Illuminate\Console\OutputStyle;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Str;
use Laravel\Boost\BoostManager;
use Laravel\Boost\Console\InstallCommand;
use Laravel\Boost\Install\GuidelineComposer;
use Laravel\Boost\Install\GuidelineConfig;
use Laravel\Boost\Install\GuidelineWriter;
use Laravel\Boost\Rules\RuleRepository;
use Laravel\Boost\Support\Config as BoostConfig;
use Symfony\Component\Console\Input\ArrayInput;
use Symfony\Component\Console\Output\BufferedOutput;

it('regenerates strict project rule guidance through the Boost writer', function (): void {
    $guidelineDirectory = storage_path('framework/testing/boost-guidance-'.Str::uuid());
    $guidelinePath = "{$guidelineDirectory}/AGENTS.md";
    $originalGuidelinePath = Config::get('boost.agents.codex.guidelines_path');
    $projectGuidance = <<<'MARKDOWN'
        # Orbit Gateway

        ## Required Guidance Bootstrap

        `.ai/rules/index.md` and every rule file indexed by it are required repository state.
        If the index or any indexed rule file is missing or unreadable, the checkout or Boost bootstrap is incomplete.
        Agents must restore or regenerate the guidance before editing.
        Never silently continue when the required project rules are absent.
        MARKDOWN;
    $projectTail = 'Project guidance after the generated block must also survive regeneration.';
    File::ensureDirectoryExists($guidelineDirectory);
    File::put(
        $guidelinePath,
        $projectGuidance
        ."\n\n===\n\n<laravel-boost-guidelines>\nstale guidance\n</laravel-boost-guidelines>\n\n{$projectTail}\n",
    );
    Config::set('boost.agents.codex.guidelines_path', $guidelinePath);

    try {
        $boost = new BoostConfig;
        $guidelineConfig = new GuidelineConfig;
        $guidelineConfig->enforceTests = true;
        $guidelineConfig->usesSail = $boost->getSail();
        $guidelineConfig->hasSkills = false;
        $guidelineConfig->hasMcp = $boost->getMcp();
        $guidelineConfig->aiGuidelines = $boost->getPackages();
        $composer = app(GuidelineComposer::class)->config($guidelineConfig);
        $effectiveGuidance = $composer->compose();
        $codexAgent = app(app(BoostManager::class)->getAgents()['codex']);
        $result = new GuidelineWriter($codexAgent)->write($effectiveGuidance);
        $regeneratedGuidance = File::get($guidelinePath);
    } finally {
        Config::set('boost.agents.codex.guidelines_path', $originalGuidelinePath);
        File::deleteDirectory($guidelineDirectory);
    }

    preg_match(
        pattern: '/<laravel-boost-guidelines>\s*(.*?)\s*<\/laravel-boost-guidelines>/s',
        subject: $regeneratedGuidance,
        matches: $regeneratedMatches,
    );
    $committedGuidance = File::get(base_path('AGENTS.md'));
    preg_match(
        pattern: '/<laravel-boost-guidelines>\s*(.*?)\s*<\/laravel-boost-guidelines>/s',
        subject: $committedGuidance,
        matches: $committedMatches,
    );
    $forbiddenFallbackPattern = '/If `?\.ai\/rules`? (?:does not exist|is absent),\s*(?:you may\s+)?(?:continue|proceed|skip)\b/i';

    expect($composer)->toBeInstanceOf(GatewayGuidelineComposer::class);
    expect($result)->toBe(GuidelineWriter::REPLACED);
    expect($regeneratedGuidance)
        ->toContain(
            $projectGuidance,
            '`.ai/rules/index.md` and every rule file indexed by it are required repository state.',
            'If the index or any indexed rule file is missing or unreadable, the checkout or Boost bootstrap is incomplete.',
            'Read every indexed rule whose globs match the files in scope before planning or editing.',
            'Stop and restore or regenerate the guidance before continuing.',
            $projectTail,
        )
        ->not->toContain(
            'stale guidance',
            'in `.ai/rules` when that directory exists',
            'If `.ai/rules` does not exist, continue without it.',
            'when that directory exists',
            'continue without it',
        )
        ->not->toMatch($forbiddenFallbackPattern);
    expect($regeneratedMatches[1] ?? null)->toBe(trim($effectiveGuidance));
    expect($committedGuidance)->not->toMatch($forbiddenFallbackPattern);
    expect($committedMatches[1] ?? null)->toBe(trim($effectiveGuidance));
});

it('fails closed when the Boost project rule source markers drift', function (string $sourceGuidance): void {
    $composer = app(GuidelineComposer::class);
    $guidelines = new ReflectionProperty(GuidelineComposer::class, 'guidelines');
    $guidelines->setValue($composer, collect([
        'boost' => [
            'content' => $sourceGuidance,
            'name' => 'boost',
            'path' => null,
            'custom' => false,
        ],
    ]));

    expect($composer->compose(...))
        ->toThrow(
            RuntimeException::class,
            'Boost project-rule guidance changed. Update the Gateway hard-stop transformation before regenerating.',
        );
})->with([
    'missing optional location' => 'If `.ai/rules` does not exist, continue without it.',
    'duplicate optional location' => implode("\n", [
        'in `.ai/rules` when that directory exists',
        'in `.ai/rules` when that directory exists',
        'If `.ai/rules` does not exist, continue without it.',
    ]),
    'missing permissive fallback' => 'in `.ai/rules` when that directory exists',
    'duplicate permissive fallback' => implode("\n", [
        'in `.ai/rules` when that directory exists',
        'If `.ai/rules` does not exist, continue without it.',
        'If `.ai/rules` does not exist, continue without it.',
    ]),
]);

it('stops managed rule regeneration before an incomplete checkout is mutated', function (
    string $state,
    string $expectedMessage,
): void {
    $projectRoot = storage_path('framework/testing/boost-managed-rules-'.Str::uuid());
    $originalBasePath = base_path();
    $rulesDirectory = "{$projectRoot}/.ai/rules";
    $indexPath = "{$rulesDirectory}/index.md";
    $missingRulePath = "{$rulesDirectory}/boost/tests.md";
    $snapshotRules = static function () use ($rulesDirectory): array {
        $snapshot = [];

        foreach (File::allFiles($rulesDirectory) as $ruleFile) {
            $relativePath = substr($ruleFile->getPathname(), strlen($rulesDirectory) + 1);
            $snapshot[$relativePath] = File::get($ruleFile->getPathname());
        }

        ksort($snapshot);

        return $snapshot;
    };

    File::copyDirectory("{$originalBasePath}/.ai/rules", $rulesDirectory);

    if ($state === 'missing index') {
        File::delete($indexPath);
    }

    if ($state === 'missing managed rule') {
        File::delete($missingRulePath);
    }

    $incompleteRules = $snapshotRules();
    app()->setBasePath($projectRoot);

    try {
        $composer = app(GuidelineComposer::class);
        $guidelineConfig = new GuidelineConfig;
        $guidelineConfig->aiGuidelines = [];
        $composer->config($guidelineConfig);
        app()->instance(RuleRepository::class, new RuleRepository($rulesDirectory));
        $resolvedCommand = app(InstallCommand::class);
        $kernel = app(Kernel::class);
        $kernel->addCommands([InstallCommand::class]);
        $kernel->setArtisan(null);
        $command = $kernel->all()['boost:install'] ?? null;

        expect($command)
            ->toBeInstanceOf(GatewayBoostInstallCommand::class)
            ->toBe($resolvedCommand);

        if (! $command instanceof GatewayBoostInstallCommand) {
            throw new LogicException('Boost install command did not resolve through the Gateway binding.');
        }

        $command->setLaravel(app());
        $command->setOutput(new OutputStyle(new ArrayInput([]), new BufferedOutput));
        $syncRuleFiles = new ReflectionMethod($command, 'syncRuleFiles');
        $thrown = null;

        try {
            $syncRuleFiles->invoke($command, $composer);
        } catch (Throwable $exception) {
            $thrown = $exception;
        }

        expect($thrown)
            ->toBeInstanceOf(RuntimeException::class)
            ->and($thrown?->getMessage())
            ->toBe($expectedMessage);

        expect($snapshotRules())->toBe($incompleteRules);

        if ($state === 'missing index') {
            expect($indexPath)->not->toBeFile();
        }

        if ($state === 'missing managed rule') {
            expect($missingRulePath)->not->toBeFile();
        }
    } finally {
        app()->setBasePath($originalBasePath);
        File::deleteDirectory($projectRoot);
    }
})->with([
    'missing index' => [
        'missing index',
        'Required project rule index is missing or unreadable: .ai/rules/index.md.',
    ],
    'missing managed rule' => [
        'missing managed rule',
        'Required indexed project rule is missing or unreadable: .ai/rules/boost/tests.md.',
    ],
]);

it('rejects duplicate project rule paths before building the effective map', function (): void {
    $projectRoot = storage_path('framework/testing/boost-duplicate-project-rule-'.Str::uuid());
    $originalBasePath = base_path();
    $rulesDirectory = "{$projectRoot}/.ai/rules";
    $indexPath = "{$rulesDirectory}/index.md";

    File::copyDirectory("{$originalBasePath}/.ai/rules", $rulesDirectory);
    File::append($indexPath, "| app/** | .ai/rules/app.md |\n");
    app()->setBasePath($projectRoot);

    try {
        expect(fn (): string => app(GuidelineComposer::class)->compose())
            ->toThrow(RuntimeException::class, 'Required project rule index contains an invalid rule row.');
    } finally {
        app()->setBasePath($originalBasePath);
        File::deleteDirectory($projectRoot);
    }
});

it('fails closed when required project rule state is incomplete', function (
    string $state,
    string $expectedMessage,
): void {
    $projectRoot = storage_path('framework/testing/boost-project-rules-'.Str::uuid());
    $originalBasePath = base_path();
    $rulesDirectory = "{$projectRoot}/.ai/rules";
    $indexPath = "{$rulesDirectory}/index.md";
    $appRulePath = "{$rulesDirectory}/app.md";
    $externalGuidancePath = storage_path('framework/testing/boost-external-guidance-'.Str::uuid());

    File::copyDirectory("{$originalBasePath}/.ai/rules", $rulesDirectory);

    if ($state === 'missing index') {
        File::delete($indexPath);
    }

    if ($state === 'empty index') {
        File::put($indexPath, "# Project Rules Index\n\nNo rules recorded yet.\n");
    }

    if ($state === 'missing indexed project rule') {
        File::delete($appRulePath);
    }

    if ($state === 'unreadable indexed project rule') {
        chmod(filename: $appRulePath, permissions: 0o000);
    }

    if ($state === 'truncated index') {
        File::put(
            $indexPath,
            <<<'MARKDOWN'
                # Project Rules Index

                | Applies to | Rule file |
                | --- | --- |
                | app/** | .ai/rules/app.md |
                MARKDOWN,
        );
    }

    if ($state === 'malformed rule row') {
        File::append($indexPath, "| app/Unsafe/** | not-a-project-rule |\n");
    }

    if ($state === 'escaping rule path') {
        File::put("{$projectRoot}/README.md", "# Not project guidance\n");
        File::put(
            $indexPath,
            <<<'MARKDOWN'
                # Project Rules Index

                | Applies to | Rule file |
                | --- | --- |
                | app/** | .ai/rules/../../README.md |
                MARKDOWN,
        );
    }

    if ($state === 'escaping rule symlink') {
        $outsideRulePath = "{$projectRoot}/outside-rule.md";
        File::put($outsideRulePath, File::get($appRulePath));
        File::delete($appRulePath);
        symlink($outsideRulePath, $appRulePath);
    }

    if ($state === 'escaping index symlink') {
        File::put($externalGuidancePath, File::get($indexPath));
        File::delete($indexPath);
        symlink($externalGuidancePath, $indexPath);
    }

    if ($state === 'escaping rules directory symlink') {
        File::copyDirectory($rulesDirectory, $externalGuidancePath);
        File::deleteDirectory($rulesDirectory);
        symlink($externalGuidancePath, $rulesDirectory);
    }

    if ($state === 'frontmatter drift') {
        File::put(
            $appRulePath,
            str_replace(
                search: "  - 'app/**'",
                replace: "  - 'other/**'",
                subject: File::get($appRulePath),
            ),
        );
    }

    app()->setBasePath($projectRoot);

    try {
        expect(fn (): string => app(GuidelineComposer::class)->compose())
            ->toThrow(RuntimeException::class, $expectedMessage);
    } finally {
        app()->setBasePath($originalBasePath);

        if ($state === 'unreadable indexed project rule') {
            chmod(filename: $appRulePath, permissions: 0o644);
        }

        if (is_link($indexPath)) {
            unlink($indexPath);
        }

        if (is_link($rulesDirectory)) {
            unlink($rulesDirectory);
        }

        File::deleteDirectory($projectRoot);
        File::deleteDirectory($externalGuidancePath);
        File::delete($externalGuidancePath);
    }
})->with([
    'missing index' => [
        'missing index',
        'Required project rule index is missing or unreadable: .ai/rules/index.md.',
    ],
    'missing indexed project rule' => [
        'missing indexed project rule',
        'Required indexed project rule is missing or unreadable: .ai/rules/app.md.',
    ],
    'unreadable indexed project rule' => [
        'unreadable indexed project rule',
        'Required indexed project rule is missing or unreadable: .ai/rules/app.md.',
    ],
    'empty index' => [
        'empty index',
        'Required project rule index contains no project rules: .ai/rules/index.md.',
    ],
    'truncated index' => [
        'truncated index',
        'Required project rule index does not match the complete project rule inventory.',
    ],
    'malformed rule row' => [
        'malformed rule row',
        'Required project rule index contains an invalid rule row.',
    ],
    'escaping rule path' => [
        'escaping rule path',
        'Required project rule index contains an unsafe rule path: .ai/rules/../../README.md.',
    ],
    'escaping rule symlink' => [
        'escaping rule symlink',
        'Required indexed project rule resolves outside .ai/rules: .ai/rules/app.md.',
    ],
    'escaping index symlink' => [
        'escaping index symlink',
        'Required project rule index resolves outside the checkout: .ai/rules/index.md.',
    ],
    'escaping rules directory symlink' => [
        'escaping rules directory symlink',
        'Required project rules directory resolves outside the checkout: .ai/rules.',
    ],
    'frontmatter drift' => [
        'frontmatter drift',
        'Indexed project rule frontmatter does not match the index: .ai/rules/app.md.',
    ],
]);
