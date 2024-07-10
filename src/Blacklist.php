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

namespace L1n6yun\HyperfJwt;

use L1n6yun\HyperfJwt\Exceptions\JwtException;
use Psr\SimpleCache\CacheInterface;
use Psr\SimpleCache\InvalidArgumentException;

class Blacklist
{
    public function __construct(private readonly CacheInterface $cache) {}

    public function add(array $payload): void
    {
        try {
            if (! empty($this->cache->get($this->getKey($payload)))) {
                return;
            }

            if ($ttl = $payload['exp'] - time()) {
                $this->cache->set($this->getKey($payload), 'forever', $ttl);
            }
        } catch (InvalidArgumentException) {
            throw new JwtException('Could not add token to blacklist');
        }
    }

    public function has(array $payload): bool
    {
        try {
            return $this->cache->has($this->getKey($payload));
        } catch (InvalidArgumentException) {
            return false;
        }
    }

    private function getKey(array $payload): string
    {
        return 'jwt:blacklist:' . $payload['jti'];
    }
}
