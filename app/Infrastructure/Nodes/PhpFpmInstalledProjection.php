<?php

declare(strict_types=1);

namespace App\Infrastructure\Nodes;

final readonly class PhpFpmInstalledProjection
{
    /**
     * @param  list<string>  $versions
     * @param  array<string, string>  $configurations
     */
    private function __construct(
        public array $versions,
        public array $configurations,
    ) {}

    public static function fromDiscoveryOutput(string $output): self
    {
        $lines = preg_split('/\R/', trim($output));
        $versions = [];
        $configurations = [];

        foreach (is_array($lines) ? $lines : [] as $line) {
            $parts = explode("\t", $line, limit: 2);
            $version = $parts[0];

            if (preg_match('/\A[0-9]+\.[0-9]+\z/', $version) !== 1) {
                continue;
            }

            $versions[] = $version;

            if (count($parts) !== 2) {
                continue;
            }

            $configuration = base64_decode($parts[1], strict: true);

            if ($configuration === false) {
                continue;
            }

            $configurations[$version] = $configuration;
        }

        return new self(
            versions: array_values(array_unique($versions)),
            configurations: $configurations,
        );
    }

    /** @return list<array{pool: string, version: string}> */
    public function pools(string $pattern): array
    {
        $pools = [];

        foreach ($this->configurations as $version => $configuration) {
            $matches = [];
            preg_match_all($pattern, $configuration, $matches);

            foreach ($matches[1] ?? [] as $pool) {
                $pools[] = ['pool' => $pool, 'version' => $version];
            }
        }

        return $pools;
    }

    public function previousConfiguration(string $version): string
    {
        return $this->configurations[$version] ?? '';
    }
}
