<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration {
    public function up(): void
    {
        Schema::create('instances', static function (Blueprint $table): void {
            $table->id();
            $table->foreignId('app_id')->constrained()->restrictOnDelete();
            $table->foreignId('node_id')->constrained()->restrictOnDelete();
            $table->string('name');
            $table->string('environment');
            $table->text('checkout_path');
            $table->string('document_root')->default('public');
            $table->string('php_version')->default('8.5');
            $table->string('hostname')->unique();
            $table->string('certificate_mode');
            $table->string('status')->default('provisioning')->index();
            $table->string('failed_step')->nullable();
            $table->string('error_code')->nullable();
            $table->timestamps();

            $table->unique(['app_id', 'name']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('instances');
    }
};
