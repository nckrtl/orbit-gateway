<?php

declare(strict_types=1);

namespace App\Infrastructure\Firewall;

final class UfwManagedCommentCounter
{
    public function count(string $output, string $comment): int
    {
        $matches = 0;

        foreach (explode("\n", $output) as $line) {
            $marker = strrpos(haystack: $line, needle: '#');

            if ($marker === false) {
                continue;
            }

            $observed = trim(substr(string: $line, offset: $marker + 1));

            if (hash_equals($comment, $observed)) {
                $matches++;
            }
        }

        return $matches;
    }
}
