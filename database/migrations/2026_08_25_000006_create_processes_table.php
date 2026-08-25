<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration {
    public function up(): void
    {
        Schema::create('processes', static function (Blueprint $table): void {
            $table->id();
            $table->string('owner_type');
            $table->unsignedBigInteger('owner_id');
            $table->string('name');
            $table->string('runtime');
            $table->text('working_directory');
            $table->json('runtime_config');
            $table->string('restart_policy')->default('unless-stopped');
            $table->string('desired_state')->default('stopped');
            $table->string('status')->default('provisioning')->index();
            $table->string('failed_step')->nullable();
            $table->string('error_code')->nullable();
            $table->timestamps();

            $table->index(['owner_type', 'owner_id']);
            $table->unique(['owner_type', 'owner_id', 'name']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('processes');
    }
};
