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

namespace L1n6yun\HyperfJwt\Aspect;

use Hyperf\Di\Annotation\Aspect;
use Hyperf\Di\Aop\AbstractAspect;
use Hyperf\Di\Aop\ProceedingJoinPoint;
use Hyperf\Di\Exception\Exception;
use L1n6yun\HyperfJwt\Annotation\Auth;
use L1n6yun\HyperfJwt\AuthManager;
use L1n6yun\HyperfJwt\Exceptions\UnauthorizedException;

#[Aspect]
class AuthAspect extends AbstractAspect
{
    public array $annotations = [
        Auth::class,
    ];

    public function __construct(private readonly AuthManager $authManager) {}

    /**
     * @throws Exception
     */
    public function process(ProceedingJoinPoint $proceedingJoinPoint): mixed
    {
        $annotation = $proceedingJoinPoint->getAnnotationMetadata();

        $authAnnotation = $annotation->class[Auth::class] ?? $annotation->method[Auth::class];

        $provider = $authAnnotation->value;

        if (! $this->authManager->setProvider($provider)->getPayload()) {
            throw new UnauthorizedException('not logged in');
        }
        return $proceedingJoinPoint->process();
    }
}
