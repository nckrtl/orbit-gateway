<?php

declare(strict_types=1);

namespace App\Providers;

use Illuminate\Support\Collection;
use Laravel\Boost\Install\GuidelineComposer;
use RuntimeException;

final class GatewayGuidelineComposer extends GuidelineComposer
{
    public function resolvedGuidelines(): Collection
    {
        return parent::resolvedGuidelines()->map($this->replaceScopedGuidance(...));
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

        $guidelines = str_replace(
            [$optionalLocation, $permissiveFallback],
            [
                'in `.ai/rules` as required repository state',
                'The complete project guidance inventory is required repository state. Run `composer guidance:check` '
                    .'before planning or editing. If it fails, make no product-code edits. Restore the exact affected '
                    .'tracked guidance path, validate again, and then run `composer guidance:update`.',
            ],
            $guidelines,
        );

        $guidelines = preg_replace(
            pattern: '/\n## (?:Frontend Bundling|Vite Error)\n.*?(?=\n(?:## |=== )|\z)/s',
            replacement: '',
            subject: $guidelines,
        );

        if (! is_string($guidelines)) {
            throw new RuntimeException('Could not remove unsupported UI guidance.');
        }

        return $guidelines;
    }

    private function replaceScopedGuidance(array $guideline): array
    {
        if (! array_key_exists(key: 'scoped', array: $guideline) || ! is_array($guideline['scoped'])) {
            return $guideline;
        }

        $guideline['scoped'] = array_map(
            static function (mixed $block): mixed {
                if (! is_array($block) || ! is_string($block['body'] ?? null)) {
                    return $block;
                }

                $block['body'] = str_replace(
                    [
                        '- For APIs, default to using Eloquent API Resources and API versioning unless existing API routes do not, then you should follow existing application convention.',
                        '- When creating new models, create useful factories and seeders for them too. Ask the user if they need any other things, using `php artisan make:model --help` to check the available options.',
                        '- After the feature tests pass, ask the user to run the complete suite with `php artisan test --compact`.',
                    ],
                    [
                        '- Keep the versioned Gateway API consistent with its existing typed Spatie Data response objects. Do not introduce Eloquent Resources beside the established contract without an explicit API migration.',
                        '- Keep models focused on persisted control-plane state. Add a factory or seeder only when an executing test or explicit bootstrap workflow needs it.',
                        '- After focused tests pass, run `composer test` with TIA and `composer test:full` without TIA before handoff.',
                    ],
                    $block['body'],
                );

                return $block;
            },
            $guideline['scoped'],
        );

        return $guideline;
    }
}
