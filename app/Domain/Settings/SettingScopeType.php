<?php

declare(strict_types=1);

namespace App\Domain\Settings;

enum SettingScopeType: string
{
    case Gateway = 'gateway';
    case Node = 'node';
    case NodeRole = 'node-role';
    case App = 'app';
    case Instance = 'instance';
    case Workspace = 'workspace';
}
