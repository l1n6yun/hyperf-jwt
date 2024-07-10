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

namespace L1n6yun\HyperfJwt\Annotation;

use Attribute;
use Hyperf\Di\Annotation\AbstractAnnotation;

#[Attribute(Attribute::TARGET_CLASS | Attribute::TARGET_METHOD)]
class Auth extends AbstractAnnotation
{
    public function __construct(public ?string $value = null) {}
}
