<?php

declare(strict_types=1);

namespace App\Infrastructure\Nodes;

use App\Domain\Nodes\NodeProjectionOperationLock;
use Closure;
use RuntimeException;
use Throwable;

/**
 * @mago-expect lint:cyclomatic-complexity The lock rejects each unsafe filesystem identity before flock.
 * @mago-expect lint:kan-defect The score reflects independent fail-closed directory, file, and handle checks.
 */
final readonly class NativeNodeProjectionOperationLock implements NodeProjectionOperationLock
{
    private const int DIRECTORY_TYPE = 0o040_000;

    private const int FILE_TYPE = 0o100_000;

    private const int TYPE_MASK = 0o170_000;

    /** @var Closure(string): (array<int|string, int>|false) */
    private Closure $pathStatus;

    /** @var Closure(resource): (array<int|string, int>|false) */
    private Closure $handleStatus;

    private int $effectiveUserId;

    /**
     * @param null|Closure(string): (array<int|string, int>|false) $pathStatus
     * @param null|Closure(resource): (array<int|string, int>|false) $handleStatus
     */
    public function __construct(
        private string $directory,
        private float $timeoutSeconds = 5.0,
        ?Closure $pathStatus = null,
        ?Closure $handleStatus = null,
        ?int $effectiveUserId = null,
    ) {
        $this->pathStatus = $pathStatus ?? static function (string $path): array|false {
            if (! file_exists($path) && ! is_link($path)) {
                return false;
            }

            return lstat($path);
        };
        $this->handleStatus = $handleStatus ?? fstat(...);
        $this->effectiveUserId = $effectiveUserId ?? posix_geteuid();
    }

    /**
     * @template TReturn
     *
     * @param Closure(): TReturn $operation
     * @return TReturn
     */
    public function synchronized(Closure $operation): mixed
    {
        $this->ensureDirectory();
        $path = $this->directory.'/node-projections.lock';
        $handle = $this->openLockFile($path);

        $acquired = false;

        try {
            $deadline = microtime(true) + $this->timeoutSeconds;

            do {
                $this->assertLockHandleIdentity($path, $handle);
                $acquired = flock($handle, LOCK_EX | LOCK_NB);

                if (! $acquired) {
                    usleep(10_000);
                }
            } while (! $acquired && microtime(true) < $deadline);

            if (! $acquired) {
                throw new RuntimeException('Could not acquire the node projection lock.');
            }

            $this->assertLockHandleIdentity($path, $handle);

            return $operation();
        } finally {
            if ($acquired) {
                flock($handle, LOCK_UN);
            }

            fclose($handle);
        }
    }

    private function ensureDirectory(): void
    {
        $status = $this->readPathStatus($this->directory);

        if ($status === false) {
            $previousMask = umask(0o077);

            try {
                $this->withoutWarnings(
                    fn (): bool => mkdir(directory: $this->directory, permissions: 0o700, recursive: true),
                );
            } finally {
                umask($previousMask);
            }

            $status = $this->readPathStatus($this->directory);

            if ($status === false) {
                throw new RuntimeException('Could not create the node projection lock directory.');
            }
        }

        $this->assertDirectoryStatus($status);
    }

    /** @return resource */
    private function openLockFile(string $path)
    {
        $status = $this->readPathStatus($path);

        if ($status === false) {
            $previousMask = umask(0o077);

            try {
                $handle = $this->withoutWarnings(static fn () => fopen(filename: $path, mode: 'x+'));
            } finally {
                umask($previousMask);
            }

            if ($handle !== false) {
                try {
                    $this->assertLockHandleIdentity($path, $handle);
                } catch (Throwable $exception) {
                    fclose($handle);

                    throw $exception;
                }

                return $handle;
            }

            $status = $this->readPathStatus($path);
        }

        if ($status === false) {
            throw new RuntimeException('Could not open the node projection lock.');
        }

        $this->assertLockFileStatus($status);
        $handle = $this->withoutWarnings(static fn () => fopen(filename: $path, mode: 'r+'));

        if ($handle === false) {
            throw new RuntimeException('Could not open the node projection lock.');
        }

        try {
            $this->assertLockHandleIdentity($path, $handle);
        } catch (Throwable $exception) {
            fclose($handle);

            throw $exception;
        }

        return $handle;
    }

    /** @param resource $handle */
    private function assertLockHandleIdentity(string $path, $handle): void
    {
        $directoryStatus = $this->readPathStatus($this->directory);

        if ($directoryStatus === false) {
            throw new RuntimeException('The node projection lock directory is unavailable.');
        }

        $this->assertDirectoryStatus($directoryStatus);
        $pathStatus = $this->readPathStatus($path);
        $handleStatus = ($this->handleStatus)($handle);

        if ($pathStatus === false || $handleStatus === false) {
            throw new RuntimeException('Could not inspect the node projection lock.');
        }

        $this->assertLockFileStatus($pathStatus);
        $this->assertLockFileStatus($handleStatus);

        if (
            $pathStatus['dev'] !== $handleStatus['dev']
            || $pathStatus['ino'] !== $handleStatus['ino']
        ) {
            throw new RuntimeException('The node projection lock pathname identity changed.');
        }
    }

    /** @return array<int|string, int>|false */
    private function readPathStatus(string $path): array|false
    {
        clearstatcache(clear_realpath_cache: true, filename: $path);

        return ($this->pathStatus)($path);
    }

    /**
     * @template TResult
     *
     * @param Closure(): TResult $operation
     * @return TResult
     */
    private function withoutWarnings(Closure $operation): mixed
    {
        set_error_handler(static fn (): bool => true);

        try {
            return $operation();
        } finally {
            restore_error_handler();
        }
    }

    /** @param array<int|string, int> $status */
    private function assertDirectoryStatus(array $status): void
    {
        if (($status['mode'] & self::TYPE_MASK) !== self::DIRECTORY_TYPE) {
            throw new RuntimeException('The node projection lock directory has an unsafe type.');
        }

        if ($status['uid'] !== $this->effectiveUserId) {
            throw new RuntimeException('The node projection lock directory has an unsafe owner.');
        }

        if (($status['mode'] & 0o7777) !== 0o700) {
            throw new RuntimeException('The node projection lock directory has an unsafe mode.');
        }
    }

    /** @param array<int|string, int> $status */
    private function assertLockFileStatus(array $status): void
    {
        if (($status['mode'] & self::TYPE_MASK) !== self::FILE_TYPE) {
            throw new RuntimeException('The node projection lock has an unsafe type.');
        }

        if ($status['uid'] !== $this->effectiveUserId) {
            throw new RuntimeException('The node projection lock has an unsafe owner.');
        }

        if (($status['mode'] & 0o7777) !== 0o600) {
            throw new RuntimeException('The node projection lock has an unsafe mode.');
        }
    }
}
