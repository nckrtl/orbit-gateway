<?php

declare(strict_types=1);

namespace App\Actions\Instances;

use App\Data\Instances\CreateInstanceData;
use App\Domain\AppDev\AppDevHostPaths;
use App\Domain\AppDev\AppDevRuntimeConverger;
use App\Domain\AppDev\RuntimeConvergenceException;
use App\Domain\AppProd\AppProdRuntimeConverger;
use App\Domain\Instances\CertificateMode;
use App\Domain\Nodes\RoleName;
use App\Domain\Shared\LifecycleStatus;
use App\Domain\Shared\ResourceOperationException;
use App\Models\App as OrbitApp;
use App\Models\Instance;
use App\Models\Node;
use Throwable;

/** @mago-expect lint:cyclomatic-complexity Instance creation keeps role, placement, and immutable identity gates together. */
final readonly class CreateInstanceAction
{
    public function __construct(
        private AppDevRuntimeConverger $runtime,
        private AppProdRuntimeConverger $productionRuntime,
        private AppDevHostPaths $hostPaths,
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

        $role = $this->resolveAppRole($node, $data);
        $this->ensureProductionSourceIdentity($instance, $app, $data, $role);
        $hostname = $role === RoleName::AppProd
            ? $this->productionHostname($data, $app, $node)
            : $this->developmentHostname($data, $app, $node);

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
            'environment' => $data->environment ?? ($role === RoleName::AppProd ? 'production' : 'development'),
            'checkout_path' => $this->hostPaths->instanceCheckout($node, $role, $app->slug, $data->name),
            'document_root' => $data->documentRoot,
            'php_version' => $data->phpVersion,
            'hostname' => $hostname,
            'certificate_mode' => $role === RoleName::AppProd ? CertificateMode::Acme : CertificateMode::OrbitCa,
            'status' => LifecycleStatus::Provisioning,
            'failed_step' => null,
            'error_code' => null,
        ])->save();

        try {
            $runtime = $role === RoleName::AppProd ? $this->productionRuntime : $this->runtime;
            $runtime->convergeInstance($instance->refresh()->load(['app', 'node']));
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

    private function resolveAppRole(Node $node, CreateInstanceData $data): RoleName
    {
        if ($node->status !== LifecycleStatus::Active) {
            throw new ResourceOperationException(
                errorCode: 'instance.node_inactive',
                message: "Node [{$node->name}] is not active.",
            );
        }

        if (! in_array(needle: $node->platform, haystack: ['linux', 'darwin'], strict: true)) {
            throw new ResourceOperationException(
                errorCode: 'instance.platform_unsupported',
                message: "Node [{$node->name}] does not support application hosting.",
            );
        }

        $roles = $node
            ->roles()
            ->whereIn('role', [RoleName::AppDev->value, RoleName::AppProd->value])
            ->where('status', LifecycleStatus::Active->value)
            ->pluck('role')
            ->map(static fn (mixed $role): RoleName => $role instanceof RoleName
                ? $role
                : RoleName::from((string) $role));

        if ($roles->count() > 1) {
            throw new ResourceOperationException(
                errorCode: 'instance.app_role_ambiguous',
                message: "Node [{$node->name}] has conflicting active application roles.",
            );
        }

        $role = $roles->first();

        if (! $role instanceof RoleName) {
            $errorCode = $data->hostname === null ? 'instance.node_not_app_dev' : 'instance.node_not_app_host';

            throw new ResourceOperationException(
                errorCode: $errorCode,
                message: "Node [{$node->name}] does not have an active application role.",
            );
        }

        if ($node->platform === 'darwin' && $role === RoleName::AppProd) {
            throw new ResourceOperationException(
                errorCode: 'instance.platform_unsupported',
                message: "Node [{$node->name}] does not support production application hosting.",
            );
        }

        return $role;
    }

    private function developmentHostname(CreateInstanceData $data, OrbitApp $app, Node $node): string
    {
        if ($node->tld === null) {
            throw new ResourceOperationException(
                errorCode: 'instance.node_tld_missing',
                message: "Node [{$node->name}] does not have a TLD.",
            );
        }

        $hostname = "{$app->slug}.{$node->tld}";

        if ($data->hostname !== null && $data->hostname !== $hostname) {
            throw new ResourceOperationException(
                errorCode: 'instance.hostname_unsupported',
                message: "An app-dev hostname must be [{$hostname}].",
            );
        }

        return $hostname;
    }

    private function productionHostname(CreateInstanceData $data, OrbitApp $app, Node $node): string
    {
        if ($data->hostname === null) {
            throw new ResourceOperationException(
                errorCode: 'instance.hostname_required',
                message: "A public hostname is required for app-prod node [{$node->name}].",
            );
        }

        if (
            preg_match('/\A[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\z/', $app->slug) !== 1
            || strlen($app->slug) > 26
            || preg_match('/\A[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\z/', $data->name) !== 1
        ) {
            throw new ResourceOperationException(
                errorCode: 'instance.production_identity_invalid',
                message: 'The production app identity cannot form a safe system user or source path.',
            );
        }

        return $data->hostname;
    }

    private function ensureProductionSourceIdentity(
        Instance $instance,
        OrbitApp $app,
        CreateInstanceData $data,
        RoleName $role,
    ): void {
        if ($role !== RoleName::AppProd || ! $instance->exists) {
            return;
        }

        $checkoutPath = "/var/www/{$app->slug}/{$data->name}";

        if ($instance->name === $data->name && $instance->checkout_path === $checkoutPath) {
            return;
        }

        throw new ResourceOperationException(
            errorCode: 'instance.source_change_unsupported',
            message: "Production instance [{$instance->name}] cannot change its source identity.",
            status: 409,
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
