<?php

declare(strict_types=1);

use App\Providers\GatewayGuidelineComposer;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Str;
use Laravel\Boost\BoostManager;
use Laravel\Boost\Install\GuidelineComposer;
use Laravel\Boost\Install\GuidelineConfig;
use Laravel\Boost\Install\GuidelineWriter;
use Laravel\Boost\Support\Config as BoostConfig;

it('regenerates strict guidance while preserving project-owned sections', function (): void {
    $guidelineDirectory = storage_path('framework/testing/boost-guidance-'.Str::uuid());
    $guidelinePath = "{$guidelineDirectory}/AGENTS.md";
    $originalGuidelinePath = Config::get('boost.agents.codex.guidelines_path');
    $committedGuidance = File::get(base_path('AGENTS.md'));
    $managedBlockStart = strpos(haystack: $committedGuidance, needle: '<laravel-boost-guidelines>');
    $managedBlockEnd = strpos(haystack: $committedGuidance, needle: '</laravel-boost-guidelines>');

    expect($managedBlockStart)->toBeInt()->and($managedBlockEnd)->toBeInt();

    $projectPrefix = substr(string: $committedGuidance, offset: 0, length: $managedBlockStart);
    $projectSuffix = substr(
        $committedGuidance,
        $managedBlockEnd + strlen('</laravel-boost-guidelines>'),
    );

    File::ensureDirectoryExists($guidelineDirectory);
    File::put(
        $guidelinePath,
        $projectPrefix."<laravel-boost-guidelines>\nstale guidance\n</laravel-boost-guidelines>".$projectSuffix,
    );
    Config::set('boost.agents.codex.guidelines_path', $guidelinePath);

    try {
        $boost = new BoostConfig;
        $guidelineConfig = new GuidelineConfig;
        $guidelineConfig->enforceTests = true;
        $guidelineConfig->usesSail = $boost->getSail();
        $guidelineConfig->hasSkills = $boost->hasSkills();
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
    preg_match(
        pattern: '/<laravel-boost-guidelines>\s*(.*?)\s*<\/laravel-boost-guidelines>/s',
        subject: $committedGuidance,
        matches: $committedMatches,
    );

    expect($composer)
        ->toBeInstanceOf(GatewayGuidelineComposer::class)
        ->and($result)
        ->toBe(GuidelineWriter::REPLACED)
        ->and($regeneratedGuidance)
        ->toStartWith($projectPrefix)
        ->toEndWith($projectSuffix)
        ->toContain(
            'The complete project guidance inventory is required repository state.',
            'Run `composer guidance:check` before planning or editing.',
            'Restore the exact affected tracked guidance path',
        )
        ->not
        ->toContain(
            'stale guidance',
            '## Frontend Bundling',
            '## Vite Error',
            '=== deployments rules ===',
            'Laravel Cloud',
            'in `.ai/rules` when that directory exists',
            'If `.ai/rules` does not exist, continue without it.',
            'when that directory exists',
            'continue without it',
        )
        ->and($regeneratedMatches[1] ?? null)
        ->toBe(trim($effectiveGuidance))
        ->and($committedMatches[1] ?? null)
        ->toBe(trim($effectiveGuidance));
});

it('fails closed when Boost changes its project rule source markers', function (string $sourceGuidance): void {
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
