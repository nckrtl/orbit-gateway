<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration {
    public function up(): void
    {
        Schema::create('node_roles', static function (Blueprint $table): void {
            $table->id();
            $table->foreignId('node_id')->constrained()->restrictOnDelete();
            $table->string('role')->index();
            $table->string('status')->default('provisioning')->index();
            $table->string('failed_step')->nullable();
            $table->string('error_code')->nullable();
            $table->timestamps();

            $table->unique(['node_id', 'role']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('node_roles');
    }
};
