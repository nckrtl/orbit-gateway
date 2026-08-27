<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration {
    public function up(): void
    {
        Schema::create('tools', static function (Blueprint $table): void {
            $table->id();
            $table->foreignId('node_id')->constrained()->cascadeOnDelete();
            $table->foreignId('tool_manager_id')->constrained('tool_managers')->cascadeOnDelete();
            $table->string('package', 255);
            $table->string('version_constraint', 255)->nullable();
            $table->boolean('protected')->default(false);
            $table->string('status', 32);
            $table->string('installed_version')->nullable();
            $table->string('failed_operation', 32)->nullable();
            $table->string('error_code')->nullable();
            $table->timestamps();

            $table->unique(['node_id', 'tool_manager_id', 'package']);
            $table->index(['node_id', 'status']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('tools');
    }
};
