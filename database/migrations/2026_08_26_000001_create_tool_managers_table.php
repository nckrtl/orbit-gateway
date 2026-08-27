<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration {
    public function up(): void
    {
        Schema::create('tool_managers', static function (Blueprint $table): void {
            $table->id();
            $table->foreignId('node_id')->constrained()->cascadeOnDelete();
            $table->string('name', 32);
            $table->string('status', 32);
            $table->string('installed_version')->nullable();
            $table->string('failed_step')->nullable();
            $table->string('error_code')->nullable();
            $table->timestamps();

            $table->unique(['node_id', 'name']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('tool_managers');
    }
};
