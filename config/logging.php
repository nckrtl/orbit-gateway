<?php

declare(strict_types=1);

use Monolog\Handler\NullHandler;
use Monolog\Handler\StreamHandler;
use Monolog\Handler\SyslogUdpHandler;
use Monolog\Processor\PsrLogMessageProcessor;

return [
    /*
     |--------------------------------------------------------------------------
     | Default Log Channel
     |--------------------------------------------------------------------------
     |
     | This option defines the default log channel that is utilized to write
     | messages to your logs. The value provided here should match one of
     | the channels present in the list of "channels" configured below.
     |
     */

    'default' => env(key: 'LOG_CHANNEL', default: 'stack'),

    /*
     |--------------------------------------------------------------------------
     | Deprecations Log Channel
     |--------------------------------------------------------------------------
     |
     | This option controls the log channel that should be used to log warnings
     | regarding deprecated PHP and library features. This allows you to get
     | your application ready for upcoming major versions of dependencies.
     |
     */

    'deprecations' => [
        'channel' => env(key: 'LOG_DEPRECATIONS_CHANNEL', default: 'null'),
        'trace' => env(key: 'LOG_DEPRECATIONS_TRACE', default: false),
    ],

    /*
     |--------------------------------------------------------------------------
     | Log Channels
     |--------------------------------------------------------------------------
     |
     | Here you may configure the log channels for your application. Laravel
     | utilizes the Monolog PHP logging library, which includes a variety
     | of powerful log handlers and formatters that you're free to use.
     |
     | Available drivers: "single", "daily", "monthly", "slack", "syslog",
     |                    "errorlog", "monolog", "custom", "stack"
     |
     */

    'channels' => [
        'stack' => [
            'driver' => 'stack',
            'channels' => explode(',', (string) env(key: 'LOG_STACK', default: 'single')),
            'ignore_exceptions' => false,
        ],

        'single' => [
            'driver' => 'single',
            'path' => storage_path('logs/laravel.log'),
            'level' => env(key: 'LOG_LEVEL', default: 'debug'),
            'replace_placeholders' => true,
        ],

        'daily' => [
            'driver' => 'daily',
            'path' => storage_path('logs/laravel.log'),
            'level' => env(key: 'LOG_LEVEL', default: 'debug'),
            'max_files' => env(key: 'LOG_DAILY_DAYS', default: 14),
            'replace_placeholders' => true,
        ],

        'monthly' => [
            'driver' => 'monthly',
            'path' => storage_path('logs/laravel.log'),
            'level' => env(key: 'LOG_LEVEL', default: 'debug'),
            'max_files' => 3,
            'replace_placeholders' => true,
        ],

        'slack' => [
            'driver' => 'slack',
            'url' => env('LOG_SLACK_WEBHOOK_URL'),
            'username' => env(
                key: 'LOG_SLACK_USERNAME',
                default: env(key: 'APP_NAME', default: 'Laravel'),
            ),
            'emoji' => env(key: 'LOG_SLACK_EMOJI', default: ':boom:'),
            'level' => env(key: 'LOG_LEVEL', default: 'critical'),
            'replace_placeholders' => true,
        ],

        'papertrail' => [
            'driver' => 'monolog',
            'level' => env(key: 'LOG_LEVEL', default: 'debug'),
            'handler' => env('LOG_PAPERTRAIL_HANDLER', SyslogUdpHandler::class),
            'handler_with' => [
                'host' => env('PAPERTRAIL_URL'),
                'port' => env('PAPERTRAIL_PORT'),
                'connectionString' => 'tls://'.env('PAPERTRAIL_URL').':'.env('PAPERTRAIL_PORT'),
            ],
            'processors' => [PsrLogMessageProcessor::class],
        ],

        'stderr' => [
            'driver' => 'monolog',
            'level' => env(key: 'LOG_LEVEL', default: 'debug'),
            'handler' => StreamHandler::class,
            'handler_with' => [
                'stream' => 'php://stderr',
            ],
            'formatter' => env('LOG_STDERR_FORMATTER'),
            'processors' => [PsrLogMessageProcessor::class],
        ],

        'syslog' => [
            'driver' => 'syslog',
            'level' => env(key: 'LOG_LEVEL', default: 'debug'),
            'facility' => env('LOG_SYSLOG_FACILITY', LOG_USER),
            'replace_placeholders' => true,
        ],

        'errorlog' => [
            'driver' => 'errorlog',
            'level' => env(key: 'LOG_LEVEL', default: 'debug'),
            'replace_placeholders' => true,
        ],

        'null' => [
            'driver' => 'monolog',
            'handler' => NullHandler::class,
        ],

        'emergency' => [
            'path' => storage_path('logs/laravel.log'),
        ],
    ],
];
