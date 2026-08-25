<?php

declare(strict_types=1);

namespace App\Domain\Settings;

use App\Models\Setting;
use Illuminate\Support\Facades\Crypt;

final readonly class SettingRepository
{
    public function put(
        SettingScope $scope,
        string $key,
        ?string $value,
        SettingValueProtection $protection = SettingValueProtection::Plain,
    ): Setting {
        $secret = match ($protection) {
            SettingValueProtection::Plain => false,
            SettingValueProtection::Secret => true,
        };

        return Setting::query()->updateOrCreate(
            [
                'scope_type' => $scope->type->value,
                'scope_id' => $scope->id,
                'key' => $key,
            ],
            [
                'value' => $secret && $value !== null ? Crypt::encryptString($value) : $value,
                'is_secret' => $secret,
            ],
        );
    }

    public function get(SettingScope $scope, string $key): ?string
    {
        $setting = Setting::query()
            ->where('scope_type', $scope->type->value)
            ->where('scope_id', $scope->id)
            ->where('key', $key)
            ->first();

        if (! $setting instanceof Setting || $setting->value === null) {
            return null;
        }

        return $setting->is_secret
            ? Crypt::decryptString($setting->value)
            : $setting->value;
    }
}
