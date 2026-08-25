<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration {
    public function up(): void
    {
        Schema::create('firewall_rules', static function (Blueprint $table): void {
            $table->id();
            $table->foreignId('node_id')->constrained()->restrictOnDelete();
            $table->string('name');
            $table->string('action');
            $table->string('source')->nullable();
            $table->string('protocol');
            $table->string('port');
            $table->string('status')->default('provisioning')->index();
            $table->string('failed_step')->nullable();
            $table->string('error_code')->nullable();
            $table->timestamps();

            $table->unique(['node_id', 'name']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('firewall_rules');
    }
};
