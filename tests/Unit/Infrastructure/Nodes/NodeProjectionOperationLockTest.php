<?php

declare(strict_types=1);

use App\Infrastructure\Nodes\NativeNodeProjectionOperationLock;
use Illuminate\Filesystem\Filesystem;

/** @mago-expect lint:halstead The security matrix keeps every fixed filesystem identity boundary in one fixture. */
describe(NativeNodeProjectionOperationLock::class, function (): void {
    beforeEach(function (): void {
        $this->directory = sys_get_temp_dir().'/orbit-node-projection-lock-'.bin2hex(random_bytes(8));
        $this->additionalCleanupPaths = [];
    });

    afterEach(function (): void {
        remove_node_projection_lock_test_path($this->directory);

        foreach ($this->additionalCleanupPaths as $path) {
            remove_node_projection_lock_test_path($path);
        }
    });

    it('uses one fixed mode-0600 lock and returns the operation result', function (): void {
        $lock = new NativeNodeProjectionOperationLock($this->directory);

        expect($lock->synchronized(static fn (): string => 'complete'))
            ->toBe('complete')
            ->and($this->directory.'/node-projections.lock')
            ->toBeFile()
            ->and(fileperms($this->directory.'/node-projections.lock') & 0o777)
            ->toBe(0o600);
    });

    it('releases the lock in finally', function (): void {
        $lock = new NativeNodeProjectionOperationLock($this->directory);

        expect(fn (): mixed => $lock->synchronized(static fn (): never => throw new RuntimeException('failure')))
            ->toThrow(RuntimeException::class, 'failure');

        expect($lock->synchronized(static fn (): string => 'recovered'))->toBe('recovered');
    });

    it('bounds contention on the same fixed lock file', function (): void {
        mkdir(directory: $this->directory, permissions: 0o700, recursive: true);
        $path = $this->directory.'/node-projections.lock';
        $handle = fopen(filename: $path, mode: 'c+');

        expect($handle)->toBeResource();
        chmod(filename: $path, permissions: 0o600);
        flock($handle, LOCK_EX);

        try {
            $lock = new NativeNodeProjectionOperationLock($this->directory, 0.01);

            expect(fn (): mixed => $lock->synchronized(static fn (): null => null))
                ->toThrow(RuntimeException::class, 'Could not acquire the node projection lock.');
        } finally {
            flock($handle, LOCK_UN);
            fclose($handle);
        }
    });

    it('rejects a symlinked lock directory without mutating its target', function (): void {
        $target = $this->directory.'-target';
        $this->additionalCleanupPaths[] = $target;
        mkdir(directory: $target, permissions: 0o700);
        symlink(target: $target, link: $this->directory);

        $lock = new NativeNodeProjectionOperationLock($this->directory);

        expect(fn (): mixed => $lock->synchronized(static fn (): string => 'must not run'))
            ->toThrow(RuntimeException::class);
        expect(is_link($this->directory))
            ->toBeTrue()
            ->and($target.'/node-projections.lock')
            ->not->toBeFile();
    });

    it('rejects a non-directory lock directory path without mutation', function (): void {
        touch($this->directory);
        chmod(filename: $this->directory, permissions: 0o600);
        $lock = new NativeNodeProjectionOperationLock($this->directory);

        expect(fn (): mixed => $lock->synchronized(static fn (): string => 'must not run'))
            ->toThrow(RuntimeException::class);
        expect($this->directory)
            ->toBeFile()
            ->and(fileperms($this->directory) & 0o777)
            ->toBe(0o600);
    });

    it('rejects an unsafe existing lock directory mode without repairing it', function (): void {
        mkdir(directory: $this->directory, permissions: 0o755);
        chmod(filename: $this->directory, permissions: 0o755);

        $lock = new NativeNodeProjectionOperationLock($this->directory);

        expect(fn (): mixed => $lock->synchronized(static fn (): string => 'must not run'))
            ->toThrow(RuntimeException::class);
        expect(fileperms($this->directory) & 0o777)->toBe(0o755);
    });

    it('rejects a lock directory not owned by the effective user', function (): void {
        mkdir(directory: $this->directory, permissions: 0o700);
        $effectiveUserId = posix_geteuid();
        $pathStatus = static function (string $path) use ($effectiveUserId): array|false {
            $status = lstat($path);

            if ($status !== false) {
                $status['uid'] = $effectiveUserId + 1;
            }

            return $status;
        };
        $lock = new NativeNodeProjectionOperationLock(
            directory: $this->directory,
            pathStatus: $pathStatus,
            effectiveUserId: $effectiveUserId,
        );

        expect(fn (): mixed => $lock->synchronized(static fn (): string => 'must not run'))
            ->toThrow(RuntimeException::class);
        expect($this->directory.'/node-projections.lock')->not->toBeFile();
    });

    it('rejects a symlinked fixed lock file without mutating its target', function (): void {
        mkdir(directory: $this->directory, permissions: 0o700);
        $target = $this->directory.'/target.lock';
        touch($target);
        chmod(filename: $target, permissions: 0o644);
        symlink(target: $target, link: $this->directory.'/node-projections.lock');
        $lock = new NativeNodeProjectionOperationLock($this->directory);

        expect(fn (): mixed => $lock->synchronized(static fn (): string => 'must not run'))
            ->toThrow(RuntimeException::class);
        expect(is_link($this->directory.'/node-projections.lock'))
            ->toBeTrue()
            ->and(fileperms($target) & 0o777)
            ->toBe(0o644);
    });

    it('rejects a non-regular fixed lock file without mutation', function (): void {
        mkdir(directory: $this->directory, permissions: 0o700);
        $path = $this->directory.'/node-projections.lock';
        mkdir(directory: $path, permissions: 0o700);
        $lock = new NativeNodeProjectionOperationLock($this->directory);

        expect(fn (): mixed => $lock->synchronized(static fn (): string => 'must not run'))
            ->toThrow(RuntimeException::class);
        expect($path)
            ->toBeDirectory()
            ->and(fileperms($path) & 0o777)
            ->toBe(0o700);
    });

    it('rejects an unsafe existing fixed lock file mode without repairing it', function (): void {
        mkdir(directory: $this->directory, permissions: 0o700);
        $path = $this->directory.'/node-projections.lock';
        touch($path);
        chmod(filename: $path, permissions: 0o644);
        $lock = new NativeNodeProjectionOperationLock($this->directory);

        expect(fn (): mixed => $lock->synchronized(static fn (): string => 'must not run'))
            ->toThrow(RuntimeException::class);
        expect(fileperms($path) & 0o777)->toBe(0o644);
    });

    it('rejects a fixed lock file not owned by the effective user', function (): void {
        mkdir(directory: $this->directory, permissions: 0o700);
        $path = $this->directory.'/node-projections.lock';
        touch($path);
        chmod(filename: $path, permissions: 0o600);
        $effectiveUserId = posix_geteuid();
        $pathStatus = static function (string $candidate) use ($effectiveUserId, $path): array|false {
            $status = lstat($candidate);

            if ($status !== false && $candidate === $path) {
                $status['uid'] = $effectiveUserId + 1;
            }

            return $status;
        };
        $lock = new NativeNodeProjectionOperationLock(
            directory: $this->directory,
            pathStatus: $pathStatus,
            effectiveUserId: $effectiveUserId,
        );

        expect(fn (): mixed => $lock->synchronized(static fn (): string => 'must not run'))
            ->toThrow(RuntimeException::class);
    });

    it('rejects pathname and open-handle identity drift before flock', function (): void {
        mkdir(directory: $this->directory, permissions: 0o700);
        $path = $this->directory.'/node-projections.lock';
        touch($path);
        chmod(filename: $path, permissions: 0o600);
        $pathReads = 0;
        $pathStatus = static function (string $candidate) use (&$pathReads, $path): array|false {
            $status = lstat($candidate);

            if ($status !== false && $candidate === $path && ++$pathReads > 1) {
                $status['ino']++;
            }

            return $status;
        };
        $lock = new NativeNodeProjectionOperationLock(
            directory: $this->directory,
            pathStatus: $pathStatus,
        );

        expect(fn (): mixed => $lock->synchronized(static fn (): string => 'must not run'))
            ->toThrow(RuntimeException::class);
    });

    it('closes a newly created lock handle when identity validation fails', function (): void {
        $openedHandle = null;
        $handleStatus = static function ($handle) use (&$openedHandle): false {
            $openedHandle = $handle;

            return false;
        };
        $lock = new NativeNodeProjectionOperationLock(
            directory: $this->directory,
            handleStatus: $handleStatus,
        );

        expect(fn (): mixed => $lock->synchronized(static fn (): string => 'must not run'))
            ->toThrow(RuntimeException::class, 'Could not inspect the node projection lock.');
        expect(is_resource($openedHandle))->toBeFalse();
    });

    it('serializes different-node aggregate operation pairs on the same file', function (
        string $first,
        string $second,
    ): void {
        $outer = new NativeNodeProjectionOperationLock($this->directory, 0.05);
        $inner = new NativeNodeProjectionOperationLock($this->directory, 0.01);
        $events = [];

        $outer->synchronized(function () use ($first, $second, $inner, &$events): void {
            $events[] = "{$first}:node-a";

            expect(fn (): mixed => $inner->synchronized(function () use ($second, &$events): void {
                $events[] = "{$second}:node-b";
            }))
                ->toThrow(RuntimeException::class, 'Could not acquire the node projection lock.');
        });

        expect($events)->toBe(["{$first}:node-a"]);
    })->with([
        'provision/provision' => ['provision', 'provision'],
        'provision/remove' => ['provision', 'remove'],
        'role-add/provision' => ['role-add', 'provision'],
        'role-add/remove' => ['role-add', 'remove'],
    ]);
});

function remove_node_projection_lock_test_path(string $path): void
{
    if (is_link($path) || is_file($path)) {
        unlink($path);

        return;
    }

    if (is_dir($path)) {
        new Filesystem()->deleteDirectory($path);
    }
}
