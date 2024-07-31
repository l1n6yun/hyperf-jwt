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

use Hyperf\Context\Context;
use Hyperf\Contract\ConfigInterface;
use L1n6yun\HyperfJwt\Contracts\JwtSubjectInterface;
use L1n6yun\HyperfJwt\Exceptions\JwtException;
use L1n6yun\HyperfJwt\Exceptions\TokenInvalidException;
use L1n6yun\HyperfJwt\RequestParser\RequestParser;
use Psr\Http\Message\ServerRequestInterface;

use function Hyperf\Support\make;

class AuthManager
{
    private array $config;

    private ?string $provider;

    public function __construct(
        private readonly Manager $manager,
        private readonly RequestParser $requestParser,
        private readonly ServerRequestInterface $request,
        ConfigInterface $config,
    ) {
        $this->config = $config->get('jwt');
    }

    public function login(JwtSubjectInterface $subject): string
    {
        $payload = [
            'sub' => $subject->getJwtIdentifier(),
            'prv' => $this->hashSubjectModel($subject),
        ];

        return $this->manager->getToken($payload);
    }

    public function check(): string
    {
        $payload = $this->getPayload();

        return $payload['sub'];
    }

    public function getPayload(): array
    {
        $payload = $this->manager->parse($this->getToken());

        $model = $this->getModel($this->provider);
        if ($this->hashSubjectModel($model) !== $payload['prv']) {
            throw new TokenInvalidException('The token provider is invalid');
        }

        return $payload;
    }

    public function logout(): void
    {
        $this->manager->invalidate($this->getToken());
    }

    public function refresh(): string
    {
        return $this->manager->refresh($this->getToken());
    }

    public function user()
    {
        $key = 'auth.user';
        $userInfo = Context::get($key);
        if ($userInfo instanceof JwtSubjectInterface) {
            return $userInfo;
        }

        $payload = $this->getPayload();

        $model = $this->getModel($this->provider);

        $userInfo = make($model)->retrieveById($payload['sub']);
        Context::set($key, $userInfo);
        return $userInfo;
    }

    public function setProvider(?string $provider): static
    {
        $this->provider = $provider ?? $this->config['provider'];

        return $this;
    }

    private function hashSubjectModel(JwtSubjectInterface|string $model): string
    {
        return sha1(is_object($model) ? get_class($model) : (string) $model);
    }

    private function getToken(): string
    {
        $key = 'auth.token';
        if (! empty($token = Context::get($key))) {
            return $token;
        }

        $token = $this->requestParser->parseToken($this->request);
        Context::set($key, $token);
        return $token;
    }

    private function getModel(string $provider)
    {
        if (empty($this->config['providers'][$provider])) {
            throw new JwtException("Does not support this provider: {$provider}");
        }
        return $this->config['providers'][$provider];
    }
}
