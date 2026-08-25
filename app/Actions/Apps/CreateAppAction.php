<?php

declare(strict_types=1);

namespace App\Actions\Apps;

use App\Data\Apps\CreateAppData;
use App\Domain\Shared\ResourceOperationException;
use App\Models\App as OrbitApp;

final readonly class CreateAppAction
{
    /** @return array{app: OrbitApp, created: bool} */
    public function execute(CreateAppData $data): array
    {
        $app = OrbitApp::query()->firstOrNew(['slug' => $data->slug]);
        $created = ! $app->exists;

        if ($app->exists && $app->repository_url !== $data->repositoryUrl) {
            throw new ResourceOperationException(
                errorCode: 'app.repository_change_unsupported',
                message: "App [{$app->slug}] cannot change its repository.",
                status: 409,
            );
        }

        $app->fill([
            'name' => $data->name,
            'repository_url' => $data->repositoryUrl,
            'defaults' => $data->defaults,
        ])->save();

        return ['app' => $app->refresh(), 'created' => $created];
    }
}
