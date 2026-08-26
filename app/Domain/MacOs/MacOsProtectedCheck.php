<?php

declare(strict_types=1);

namespace App\Domain\MacOs;

enum MacOsProtectedCheck: string
{
    case RemoteLogin = 'remote-login';
    case PfAnchor = 'pf-anchor';
    case Resolver = 'resolver';
    case Dnsmasq = 'dnsmasq';
    case RootCaTrust = 'root-ca-trust';
}
