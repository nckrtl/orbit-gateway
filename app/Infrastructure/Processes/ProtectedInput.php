<?php

declare(strict_types=1);

namespace App\Infrastructure\Processes;

use LogicException;
use RuntimeException;
use SensitiveParameter;
use Throwable;

final class ProtectedInput
{
    /** @var resource|null */
    private mixed $stream;

    /** @param resource $stream */
    private function __construct(mixed $stream)
    {
        $this->stream = $stream;
    }

    public function __destruct()
    {
        $this->close();
    }

    public static function fromString(#[SensitiveParameter] string $contents): self
    {
        $stream = tmpfile();

        if ($stream === false) {
            throw new RuntimeException('Unable to create protected process input.');
        }

        $input = new self($stream);

        try {
            $metadata = stream_get_meta_data($stream);
            $path = $metadata['uri'];

            if (! chmod(filename: $path, permissions: 0o600)) {
                throw new RuntimeException('Unable to protect process input.');
            }

            $length = strlen($contents);
            $offset = 0;

            while ($offset < $length) {
                $written = fwrite($stream, substr($contents, $offset));

                if ($written === false || $written === 0) {
                    throw new RuntimeException('Unable to write protected process input.');
                }

                $offset += $written;
            }
        } catch (Throwable $exception) {
            $input->close();

            throw $exception;
        }

        return $input;
    }

    /** @return resource */
    public function stream(): mixed
    {
        if (! is_resource($this->stream)) {
            throw new LogicException('Protected process input is closed.');
        }

        if (! rewind($this->stream)) {
            throw new RuntimeException('Unable to read protected process input.');
        }

        return $this->stream;
    }

    public function close(): void
    {
        if (! is_resource($this->stream)) {
            return;
        }

        fclose($this->stream);
        $this->stream = null;
    }

    /** @return array{input: string} */
    public function __debugInfo(): array
    {
        return ['input' => '[PROTECTED]'];
    }
}
