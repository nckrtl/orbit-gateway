<?php

declare(strict_types=1);

namespace App\Infrastructure\MacOs;

/** @mago-expect lint:too-many-methods Fixed methods keep every user runtime path explicit and typo-safe. */
final readonly class MacOsFilesystemLayout
{
    public function caddyRoot(string $home): string
    {
        return "{$home}/.orbit/caddy";
    }

    public function caddyCurrent(string $home): string
    {
        return $this->caddyRoot($home).'/Caddyfile';
    }

    public function caddyLock(string $home): string
    {
        return "{$home}/.orbit/run/caddy.lock";
    }

    public function caddyLog(string $home): string
    {
        return "{$home}/.orbit/logs/caddy.log";
    }

    public function phpCurrent(string $home, string $version): string
    {
        return "{$home}/.orbit/php/{$version}/php-fpm.conf";
    }

    public function phpLock(string $home, string $version): string
    {
        return "{$home}/.orbit/run/php/php-fpm-{$version}.lock";
    }

    public function phpSocket(string $home, string $scope): string
    {
        return "{$home}/.orbit/run/php/orbit-{$scope}.sock";
    }

    public function phpHealthSocket(string $home, string $version): string
    {
        return "{$home}/.orbit/run/php/health-{$version}.sock";
    }

    public function phpLog(string $home, string $version): string
    {
        return "{$home}/.orbit/logs/php-fpm-{$version}.log";
    }

    public function certificateCurrent(string $home, string $scope): string
    {
        return "{$home}/.orbit/certificates/{$scope}/current";
    }

    public function launchAgent(string $home, string $label): string
    {
        return "{$home}/Library/LaunchAgents/{$label}.plist";
    }
}
