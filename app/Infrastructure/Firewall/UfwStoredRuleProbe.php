<?php

declare(strict_types=1);

namespace App\Infrastructure\Firewall;

final class UfwStoredRuleProbe
{
    /** @return non-empty-list<string> */
    public static function arguments(): array
    {
        return [
            'sudo',
            'awk',
            <<<'AWK'
                /^### tuple ### / {
                    family = FILENAME == "/etc/ufw/user6.rules" ? "v6" : "v4"
                    print "__orbit_ufw_tuple:" family ":" $0
                }
                AWK,
            '/etc/ufw/user.rules',
            '/etc/ufw/user6.rules',
        ];
    }
}
