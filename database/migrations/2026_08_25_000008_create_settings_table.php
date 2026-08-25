<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration {
    public function up(): void
    {
        Schema::create('settings', static function (Blueprint $table): void {
            $table->id();
            $table->string('scope_type')->index();
            $table->unsignedBigInteger('scope_id')->default(0);
            $table->string('key');
            $table->text('value')->nullable();
            $table->boolean('is_secret')->default(false);
            $table->timestamps();

            $table->unique(['scope_type', 'scope_id', 'key']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('settings');
    }
};
