# Hyperf JWT 组件

[![Latest Stable Version](https://poser.pugx.org/l1n6yun/hyperf-jwt/v/stable)](https://packagist.org/packages/l1n6yun/hyperf-jwt)
[![Latest Unstable Version](https://poser.pugx.org/l1n6yun/hyperf-jwt/v/unstable)](https://packagist.org/packages/l1n6yun/hyperf-jwt)
[![License](https://poser.pugx.org/l1n6yun/hyperf-jwt/license)](https://packagist.org/packages/l1n6yun/hyperf-jwt)
[![PHPUnit](https://github.com/l1n6yun/hyperf-jwt/actions/workflows/test.yml/badge.svg)](https://github.com/l1n6yun/hyperf-jwt/actions/workflows/test.yml)
[![Release](https://github.com/l1n6yun/hyperf-jwt/actions/workflows/release.yml/badge.svg)](https://github.com/l1n6yun/hyperf-jwt/actions/workflows/release.yml)

## 安装

```shell
composer require l1n6yun/hyperf-jwt
```

## 发布配置

```shell
php bin/hyperf.php vendor:publish l1n6yun/hyperf-jwt
```

> 文件位于 `config/autoload/jwt.php`。

## 配置

```php
<?php

declare(strict_types=1);

use function Hyperf\Support\env;

return [
    'algo' => env('JWT_ALGO', 'HS256'),
    'secret' => env('JWT_SECRET'),
    'ttl' => env('JWT_TTL', 86400),
    'leeway' => env('JWT_LEEWAY', 0),
    'keys' => [
        'public' => env('JWT_PUBLIC_KEY'),
        'private' => env('JWT_PRIVATE_KEY'),
        'passphrase' => env('JWT_PASSPHRASE'),
    ],
    'provider' => 'user',
    'providers' => [
        'user' => \App\Models\UserModel::class, // 需实现 JwtSubjectInterface 接口
    ],
];

```

### 生成秘钥

```shell
php bin/hyperf.php gen:jwt-secret

#php bin/hyperf.php gen:jwt-public-key
```

## 使用

```php

use L1n6yun\HyperfJwt\Contracts\JwtSubjectInterface;

use function L1n6yun\HyperfJwt\auth;

// 模型实现了 JwtSubjectInterface 接口
class UserModel implements JwtSubjectInterface{
    public function getJwtIdentifier(){
        return $this->id;
    };
    
    public static function retrieveById($key){
        return self::findFromCache($key);
    };
}

// 生成token
$userInfo = UserModel::query()->first();
auth()->login($userInfo)

// 退出登陆
auth()->logout();

// 获取载荷
auth()->getPayload();

// 获取用户信息
auth()->user();

// 刷新token
auth()->refresh();

// 检测登陆返回用户ID
auth()->check();
```

### 使用注解进行权限验证，注解适用于类和方法

```php
<?php
namespace App\Controller;
use L1n6yun\HyperfJwt\Annotation\Auth;

#[Auth] // 全局注解，所有方法都需要验证
class TestController extends AbstractController
{
    #[Auth] // 方法注解，该方法需要验证
    public function userInfo(){
        
    }
}
```

### 异常助理

使用 `L1n6yun\HyperfJwt\Exceptions\Handlers\AuthExceptionHandler` ，此步骤可选，开发者可以自行捕捉 `AuthException` 和 `UnauthorizedException` 进行处理

```php
# config/autoload/exceptions.php
use L1n6yun\HyperfJwt\Exceptions\Handlers\AuthExceptionHandler

return [
    'handler' => [
        'http' => [
            AuthExceptionHandler::class,
        ],
    ],
];
```
