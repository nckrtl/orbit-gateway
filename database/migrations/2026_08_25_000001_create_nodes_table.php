<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration {
    public function up(): void
    {
        Schema::create('nodes', static function (Blueprint $table): void {
            $table->id();
            $table->string('name')->unique();
            $table->string('status')->default('provisioning')->index();
            $table->string('platform')->default('linux');
            $table->string('architecture')->nullable();
            $table->string('public_ssh_host');
            $table->unsignedSmallInteger('public_ssh_port')->default(22);
            $table->string('ssh_user')->default('root');
            $table->string('wireguard_address')->nullable()->unique();
            $table->text('wireguard_public_key')->nullable();
            $table->string('wireguard_endpoint_override')->nullable();
            $table->string('dns_server_override')->nullable();
            $table->string('ssh_host_key_type')->nullable();
            $table->text('ssh_host_key')->nullable();
            $table->string('ssh_host_fingerprint')->nullable();
            $table->string('failed_step')->nullable();
            $table->string('error_code')->nullable();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('nodes');
    }
};
