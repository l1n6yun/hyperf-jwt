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

use Hyperf\Contract\ConfigInterface;
use Hyperf\Stringable\Str;
use L1n6yun\HyperfJwt\Exceptions\TokenBlacklistedException;
use Lcobucci\JWT\Token\RegisteredClaims;

use function Hyperf\Support\make;

class Manager
{
    private array $config;

    private Codec $codec;

    public function __construct(
        private readonly Blacklist $blacklist,
        ConfigInterface $config
    ) {
        $this->config = $config->get('jwt');

        // make Codec
        $secret = base64_decode($this->config['secret'] ?? '');
        $leeway = $this->config['leeway'];
        $algo = $this->config['algo'] ?? 'HS256';
        $keys = $this->config['keys'] ?? [];
        if (! empty($keys)) {
            $keys['passphrase'] = empty($keys['passphrase']) ? null : base64_decode($keys['passphrase']);
        }
        $this->codec = make(Codec::class, compact('secret', 'algo', 'keys', 'leeway'));
    }

    public function getToken(array $payload): string
    {
        $time = time();
        $payload = array_merge($payload, [
            RegisteredClaims::ISSUED_AT => $time,
            RegisteredClaims::NOT_BEFORE => $time,
            RegisteredClaims::EXPIRATION_TIME => $time + $this->config['ttl'],
            RegisteredClaims::ID => $this->getJti(),
        ]);

        return $this->codec->encode($payload);
    }

    public function parse(string $token, bool $checkBlacklist = true): array
    {
        $payload = $this->codec->decode($token);

        if ($checkBlacklist && $this->blacklist->has($payload)) {
            throw new TokenBlacklistedException('The token has been blacklisted');
        }

        return $payload;
    }

    public function refresh(string $token): string
    {
        $oldPayload = $this->parse($token);

        $this->blacklist->add($oldPayload);

        $payload = [
            'sub' => $oldPayload['sub'],
            'prv' => $oldPayload['prv'],
            'jti' => $this->getJti(),
        ];
        return $this->getToken($payload);
    }

    public function invalidate(string $token): void
    {
        $payload = $this->parse($token, false);

        $this->blacklist->add($payload);
    }

    private function getJti(): string
    {
        return Str::random(32);
    }
}
