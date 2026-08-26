<?php

declare(strict_types=1);

namespace App\Http\Controllers\Api;

use App\Domain\Certificates\LeafCertificateSigner;
use App\Http\Controllers\Controller;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use RuntimeException;
use Throwable;

final class RootCaCertificatesController extends Controller
{
    public function show(Request $request, LeafCertificateSigner $certificates): JsonResponse
    {
        try {
            $certificate = $certificates->rootCertificate();
            /** @mago-expect analysis:invalid-argument OpenSSL accepts PEM strings at runtime. */
            $fingerprint = openssl_x509_fingerprint($certificate, digest_algo: 'sha256');

            if (! is_string($fingerprint)) {
                throw new RuntimeException('The configured root CA certificate is invalid.');
            }
        } catch (Throwable) {
            $request->attributes->set('orbit.error_code', 'ca.unavailable');

            return response()->json([
                'error' => [
                    'code' => 'ca.unavailable',
                    'message' => 'Gateway root CA is unavailable.',
                    'details' => [],
                ],
            ], 503);
        }

        return response()->json([
            'data' => [
                'root_ca' => $certificate,
                'sha256' => $fingerprint,
            ],
            'meta' => [
                'request_id' => $request->attributes->getString('orbit.request_id'),
            ],
        ]);
    }
}
