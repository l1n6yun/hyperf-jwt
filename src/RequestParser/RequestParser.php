<?php

declare(strict_types=1);
/**
 * This file is part of l1n6yun/hyperf-jwt.
 *
 * @link     https://github.com/l1n6yun/hyperf-jwt
 * @document https://github.com/l1n6yun/hyperf-jwt/blob/master/README.md
 * @contact  l1n6yun@gmail.com
 * @license  https://github.com/l1n6yun/hyperf-jwt/blob/master/LICENSE
 */

namespace L1n6yun\HyperfJwt\RequestParser;

use L1n6yun\HyperfJwt\Exceptions\JwtException;
use L1n6yun\HyperfJwt\RequestParser\Handlers\AuthHeaders;
use L1n6yun\HyperfJwt\RequestParser\Handlers\Cookies;
use Psr\Http\Message\ServerRequestInterface;

class RequestParser
{
    public function parseToken(ServerRequestInterface $request): string
    {
        $handlers = [
            new AuthHeaders(),
            new Cookies(),
        ];

        foreach ($handlers as $handler) {
            $token = $handler->parse($request);
            if ($token) {
                return $token;
            }
        }
        throw new JwtException('A token is required');
    }
}
