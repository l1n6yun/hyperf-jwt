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

namespace L1n6yun\HyperfJwt\RequestParser\Handlers;

use L1n6yun\HyperfJwt\Contracts\RequestParser\HandlerInterface;
use Psr\Http\Message\ServerRequestInterface;

use function Hyperf\Collection\data_get;

class Cookies implements HandlerInterface
{
    public function parse(ServerRequestInterface $request): ?string
    {
        return data_get($request->getCookieParams(), 'token');
    }
}
