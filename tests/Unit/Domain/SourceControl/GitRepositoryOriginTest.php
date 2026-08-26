<?php

declare(strict_types=1);

use App\Domain\SourceControl\GitRepositoryOrigin;

it('accepts supported Git repository origins', function (string $repository): void {
    expect(GitRepositoryOrigin::isValid($repository))
        ->toBeTrue()
        ->and(GitRepositoryOrigin::validate($repository))
        ->toBe($repository);
})->with([
    'HTTPS URL' => ['https://github.com/owner/repository.git'],
    'SSH URL with user' => ['ssh://git@github.com/owner/repository.git'],
    'SSH URL without user' => ['ssh://github.com/owner/repository.git'],
    'scp-like SSH URL' => ['git@github.com:owner/repository.git'],
]);

it('rejects unsafe or unsupported Git repository origins', function (string $repository): void {
    expect(GitRepositoryOrigin::isValid($repository))->toBeFalse();
    expect(fn (): string => GitRepositoryOrigin::validate($repository))
        ->toThrow(InvalidArgumentException::class, 'The Git repository origin is invalid.');
})->with([
    'embedded HTTPS credentials' => ['https://token@github.com/owner/repository.git'],
    'embedded HTTPS password' => ['https://user:secret@github.com/owner/repository.git'],
    'embedded SSH password' => ['ssh://git:secret@github.com/owner/repository.git'],
    'empty embedded SSH password' => ['ssh://git:@github.com/owner/repository.git'],
    'query string' => ['https://github.com/owner/repository.git?token=secret'],
    'fragment' => ['https://github.com/owner/repository.git#main'],
    'scp-like query string' => ['git@github.com:owner/repository.git?token=secret'],
    'scp-like fragment' => ['git@github.com:owner/repository.git#main'],
    'control character' => ["https://github.com/owner/repository.git\n--upload-pack=payload"],
    'Unicode whitespace in URL' => ["https://github.com/owner/repository\u{00a0}evil.git"],
    'Unicode whitespace in scp-like URL' => ["git@github.com:owner/repository\u{00a0}evil.git"],
    'unsupported file scheme' => ['file:///tmp/repository'],
    'unsupported FTP scheme' => ['ftp://example.test/owner/repository.git'],
    'unsupported Git scheme' => ['git://example.test/owner/repository.git'],
    'absolute plain path' => ['/tmp/repository'],
    'relative plain path' => ['owner/repository'],
    'Unicode line separator' => ["https://example.test/owner/repository\u{2028}evil.git"],
    'Unicode paragraph separator' => ["https://example.test/owner/repository\u{2029}evil.git"],
    'Unicode format character' => ["https://example.test/owner/repository\u{200b}evil.git"],
    'Unicode private-use character' => ["https://example.test/owner/repository\u{e000}evil.git"],
    'Unicode unassigned character' => ["https://example.test/owner/repository\u{0378}evil.git"],
    'malformed UTF-8' => ["https://example.test/owner/repository\xc3\x28.git"],
]);

it('uses a bounded exception that does not expose embedded credentials in debug output', function (): void {
    $sentinel = 'sentinel-repository-password';
    $repository = "ssh://git:{$sentinel}@example.test/owner/repository.git";
    $exception = null;

    try {
        GitRepositoryOrigin::validate($repository);
    } catch (InvalidArgumentException $caught) {
        $exception = $caught;
    }

    expect($exception)
        ->toBeInstanceOf(InvalidArgumentException::class)
        ->and($exception?->getMessage())
        ->toBe('The Git repository origin is invalid.');

    $appOwnedTrace = array_values(array_filter(
        $exception?->getTrace() ?? [],
        static fn (array $frame): bool => (
            is_string($frame['class'] ?? null) && str_starts_with($frame['class'], 'App\\')
        ),
    ));
    $debugOutput = json_encode([
        'message' => $exception?->getMessage(),
        'trace' => $appOwnedTrace,
    ], JSON_THROW_ON_ERROR);

    expect($debugOutput)->not->toContain($sentinel, $repository);
});
