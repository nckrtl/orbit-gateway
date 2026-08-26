<?php

declare(strict_types=1);

use Illuminate\Support\Str;

return [
    /*
     |--------------------------------------------------------------------------
     | Default Cache Store
     |--------------------------------------------------------------------------
     |
     | This option controls the default cache store that will be used by the
     | framework. This connection is utilized if another isn't explicitly
     | specified when running a cache operation inside the application.
     |
     */

    'default' => env(key: 'CACHE_STORE', default: 'database'),

    /*
     |--------------------------------------------------------------------------
     | Cache Stores
     |--------------------------------------------------------------------------
     |
     | Here you may define all of the cache "stores" for your application as
     | well as their drivers. You may even define multiple stores for the
     | same cache driver to group types of items stored in your caches.
     |
     | Supported drivers: "array", "database", "file", "memcached",
     |                    "redis", "dynamodb", "storage", "octane",
     |                    "session", "failover", "null"
     |
     */

    'stores' => [
        'array' => [
            'driver' => 'array',
            'serialize' => false,
        ],

        'database' => [
            'driver' => 'database',
            'connection' => env('DB_CACHE_CONNECTION'),
            'table' => env(key: 'DB_CACHE_TABLE', default: 'cache'),
            'lock_connection' => env('DB_CACHE_LOCK_CONNECTION'),
            'lock_table' => env('DB_CACHE_LOCK_TABLE'),
        ],

        'file' => [
            'driver' => 'file',
            'path' => storage_path('framework/cache/data'),
            'lock_path' => storage_path('framework/cache/data'),
        ],

        'storage' => [
            'driver' => 'storage',
            'disk' => env('CACHE_STORAGE_DISK'),
            'path' => env(key: 'CACHE_STORAGE_PATH', default: 'framework/cache/data'),
        ],

        'memcached' => [
            'driver' => 'memcached',
            'persistent_id' => env('MEMCACHED_PERSISTENT_ID'),
            'sasl' => [
                env('MEMCACHED_USERNAME'),
                env('MEMCACHED_PASSWORD'),
            ],
            'options' => [
                // Memcached::OPT_CONNECT_TIMEOUT => 2000,
            ],
            'servers' => [
                [
                    'host' => env(key: 'MEMCACHED_HOST', default: '127.0.0.1'),
                    'port' => env(key: 'MEMCACHED_PORT', default: 11_211),
                    'weight' => 100,
                ],
            ],
        ],

        'redis' => [
            'driver' => 'redis',
            'connection' => env(key: 'REDIS_CACHE_CONNECTION', default: 'cache'),
            'lock_connection' => env(key: 'REDIS_CACHE_LOCK_CONNECTION', default: 'default'),
        ],

        'dynamodb' => [
            'driver' => 'dynamodb',
            'key' => env('AWS_ACCESS_KEY_ID'),
            'secret' => env('AWS_SECRET_ACCESS_KEY'),
            'region' => env(key: 'AWS_DEFAULT_REGION', default: 'us-east-1'),
            'table' => env(key: 'DYNAMODB_CACHE_TABLE', default: 'cache'),
            'endpoint' => env('DYNAMODB_ENDPOINT'),
        ],

        'octane' => [
            'driver' => 'octane',
        ],

        'failover' => [
            'driver' => 'failover',
            'stores' => [
                'database',
                'array',
            ],
        ],
    ],

    /*
     |--------------------------------------------------------------------------
     | Cache Key Prefix
     |--------------------------------------------------------------------------
     |
     | When utilizing the APC, database, memcached, Redis, and DynamoDB cache
     | stores, there might be other applications using the same cache. For
     | that reason, you may prefix every cache key to avoid collisions.
     |
     */

    'prefix' => env(
        key: 'CACHE_PREFIX',
        default: Str::slug((string) env(key: 'APP_NAME', default: 'laravel')).'-cache-',
    ),

    /*
     |--------------------------------------------------------------------------
     | Serializable Classes
     |--------------------------------------------------------------------------
     |
     | This value determines the classes that can be unserialized from cache
     | storage. By default, no PHP classes will be unserialized from your
     | cache to prevent gadget chain attacks if your APP_KEY is leaked.
     |
     */

    'serializable_classes' => false,
];
