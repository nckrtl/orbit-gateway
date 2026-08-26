<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration {
    public function up(): void
    {
        Schema::create('node_access', static function (Blueprint $table): void {
            $table->id();
            $table->foreignId('consumer_node_id')->constrained('nodes')->cascadeOnDelete();
            $table->foreignId('serving_node_id')->constrained('nodes')->cascadeOnDelete();
            $table->timestamps();

            $table->unique(['consumer_node_id', 'serving_node_id']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('node_access');
    }
};
