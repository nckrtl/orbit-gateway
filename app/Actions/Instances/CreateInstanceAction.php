<?php

declare(strict_types=1);

namespace App\Actions\Instances;

use App\Data\Instances\CreateInstanceData;
use App\Domain\AppDev\AppDevRuntimeConverger;
use App\Domain\AppDev\RuntimeConvergenceException;
use App\Domain\Instances\CertificateMode;
use App\Domain\Nodes\RoleName;
use App\Domain\Shared\LifecycleStatus;
use App\Domain\Shared\ResourceOperationException;
use App\Models\App as OrbitApp;
use App\Models\Instance;
use App\Models\Node;
use Throwable;

final readonly class CreateInstanceAction
{
    public function __construct(
        private AppDevRuntimeConverger $runtime,
    ) {}

    /** @return array{instance: Instance, created: bool} */
    public function execute(CreateInstanceData $data): array
    {
        $app = OrbitApp::query()->findOrFail($data->appId);
        $node = Node::query()->findOrFail($data->nodeId);
        $instance = Instance::query()->firstOrNew([
            'app_id' => $app->id,
            'node_id' => $node->id,
        ]);
        $created = ! $instance->exists;

        $this->ensureAppDevNode($node);

        $hostname = "{$app->slug}.{$node->name}.".(string) config('orbit.app_dev_domain');

        if (filter_var($hostname, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) === false) {
            throw new ResourceOperationException(
                errorCode: 'instance.hostname_invalid',
                message: "Derived hostname [{$hostname}] is invalid.",
            );
        }

        $collision = Instance::query()
            ->where('hostname', $hostname)
            ->when($instance->exists, static fn ($query) => $query->whereKeyNot($instance->id))
            ->exists();

        if ($collision) {
            throw new ResourceOperationException(
                errorCode: 'instance.hostname_taken',
                message: "Hostname [{$hostname}] is already in use.",
                status: 409,
            );
        }

        $instance->fill([
            'name' => $data->name,
            'node_id' => $node->id,
            'environment' => $data->environment,
            'checkout_path' => "/home/orbit/apps/{$app->slug}",
            'document_root' => $data->documentRoot,
            'php_version' => $data->phpVersion,
            'hostname' => $hostname,
            'certificate_mode' => CertificateMode::OrbitCa,
            'status' => LifecycleStatus::Provisioning,
            'failed_step' => null,
            'error_code' => null,
        ])->save();

        try {
            $this->runtime->convergeInstance($instance->refresh()->load(['app', 'node']));
        } catch (RuntimeConvergenceException $exception) {
            $this->markFailed($instance, $exception);

            throw $exception;
        } catch (Throwable $exception) {
            $failure = new RuntimeConvergenceException(
                step: 'unknown',
                errorCode: 'instance.provision_failed',
                message: 'Instance provisioning failed.',
                previous: $exception,
            );
            $this->markFailed($instance, $failure);

            throw $failure;
        }

        $this->markActive($instance);

        return ['instance' => $instance->refresh(), 'created' => $created];
    }

    private function ensureAppDevNode(Node $node): void
    {
        $hasRole = $node->status === LifecycleStatus::Active && $node
            ->roles()
            ->where('role', RoleName::AppDev->value)
            ->where('status', LifecycleStatus::Active->value)
            ->exists();

        if ($hasRole) {
            return;
        }

        throw new ResourceOperationException(
            errorCode: 'instance.node_not_app_dev',
            message: "Node [{$node->name}] does not have an active app-dev role.",
        );
    }

    private function markActive(Instance $instance): void
    {
        $instance->update([
            'status' => LifecycleStatus::Active,
            'failed_step' => null,
            'error_code' => null,
        ]);
    }

    private function markFailed(Instance $instance, RuntimeConvergenceException $exception): void
    {
        $instance->update([
            'status' => LifecycleStatus::Failed,
            'failed_step' => $exception->step,
            'error_code' => $exception->errorCode,
        ]);
    }
}
