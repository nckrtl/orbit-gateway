<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration {
    public function up(): void
    {
        Schema::create('activity_log', static function (Blueprint $table): void {
            $table->id();
            $table->string('log_name')->nullable()->index();
            $table->text('description');
            $table->nullableMorphs('subject', 'subject');
            $table->nullableMorphs('causer', 'causer');
            $table->string('event')->nullable();
            $table->json('properties')->nullable();
            $table->json('attribute_changes')->nullable();
            $table->uuid('batch_uuid')->nullable();
            $table->uuid('request_id')->index();
            $table->string('command')->index();
            $table->foreignId('caller_node_id')->nullable()->constrained('nodes')->nullOnDelete();
            $table->foreignId('target_node_id')->nullable()->constrained('nodes')->nullOnDelete();
            $table->string('caller_ip')->nullable();
            $table->string('status')->index();
            $table->unsignedBigInteger('duration_ms')->nullable();
            $table->integer('exit_code')->nullable();
            $table->string('error_code')->nullable()->index();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('activity_log');
    }
};
