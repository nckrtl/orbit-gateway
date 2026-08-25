<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration {
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        $duplicate = DB::table('instances')
            ->select(['app_id', 'node_id'])
            ->groupBy(['app_id', 'node_id'])
            ->havingRaw('COUNT(*) > 1')
            ->first();

        if ($duplicate !== null) {
            throw new \RuntimeException(
                'Cannot enforce one instance per app and node while duplicate placements exist.',
            );
        }

        Schema::table('instances', static function (Blueprint $table): void {
            $table->unique(['app_id', 'node_id']);
        });

        Schema::table('instances', static function (Blueprint $table): void {
            $table->dropUnique(['app_id', 'name']);
        });
    }

    /**
     * Reverse the migrations.
     */
};
