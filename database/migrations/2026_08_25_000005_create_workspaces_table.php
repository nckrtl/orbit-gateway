<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration {
    public function up(): void
    {
        Schema::create('workspaces', static function (Blueprint $table): void {
            $table->id();
            $table->foreignId('instance_id')->constrained()->restrictOnDelete();
            $table->string('name');
            $table->string('branch');
            $table->text('checkout_path');
            $table->string('php_version')->nullable();
            $table->string('hostname')->unique();
            $table->string('status')->default('provisioning')->index();
            $table->string('failed_step')->nullable();
            $table->string('error_code')->nullable();
            $table->timestamps();

            $table->unique(['instance_id', 'name']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('workspaces');
    }
};
