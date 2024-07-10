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

use DateInterval;
use DateTimeImmutable;
use Exception;
use Hyperf\Collection\Arr;
use L1n6yun\HyperfJwt\Exceptions\JwtException;
use L1n6yun\HyperfJwt\Exceptions\TokenInvalidException;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Encoding\CannotDecodeContent;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Blake2b as BLAKE2B;
use Lcobucci\JWT\Signer\Ecdsa\Sha256 as ES256;
use Lcobucci\JWT\Signer\Ecdsa\Sha384 as ES384;
use Lcobucci\JWT\Signer\Ecdsa\Sha512 as ES512;
use Lcobucci\JWT\Signer\Eddsa as EdDSA;
use Lcobucci\JWT\Signer\Hmac\Sha256 as HS256;
use Lcobucci\JWT\Signer\Hmac\Sha384 as HS384;
use Lcobucci\JWT\Signer\Hmac\Sha512 as HS512;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256 as RS256;
use Lcobucci\JWT\Signer\Rsa\Sha384 as RS384;
use Lcobucci\JWT\Signer\Rsa\Sha512 as RS512;
use Lcobucci\JWT\Token\InvalidTokenStructure;
use Lcobucci\JWT\Token\RegisteredClaims;
use Lcobucci\JWT\Token\UnsupportedHeaderFound;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Constraint\StrictValidAt;
use Symfony\Component\Clock\Clock;

class Codec
{
    private Configuration $configuration;

    private string $secret;

    private string $algo;

    private array $keys;

    private array $signers = [
        'HS256' => HS256::class,
        'HS384' => HS384::class,
        'HS512' => HS512::class,
        'BLAKE2B' => BLAKE2B::class,
        'ES256' => ES256::class,
        'ES384' => ES384::class,
        'ES512' => ES512::class,
        'RS256' => RS256::class,
        'RS384' => RS384::class,
        'RS512' => RS512::class,
        'EdDSA' => EdDSA::class,
    ];

    private array $asymmetric = ['HS256' => false,
        'HS384' => false,
        'HS512' => false,
        'BLAKE2B' => false,
        'ES256' => true,
        'ES384' => true,
        'ES512' => true,
        'RS256' => true,
        'RS384' => true,
        'RS512' => true,
        'EdDSA' => true];

    /**
     * @throws Exception
     */
    public function __construct(string $secret, string $algo, array $keys, int $leeway)
    {
        $this->secret = $secret;
        $this->algo = $algo;
        $this->keys = $keys;

        $signer = $this->getSigner();

        if ($this->isAsymmetric()) {
            $this->configuration = Configuration::forAsymmetricSigner($signer, $this->getSigningKey(), $this->getVerificationKey());
        } else {
            $this->configuration = Configuration::forSymmetricSigner($signer, InMemory::plainText($this->getSecret()));
        }

        $intervalSpec = 'PT' . $leeway . 'S';
        $this->configuration->setValidationConstraints(
            new StrictValidAt(Clock::get(), new DateInterval($intervalSpec)),
            new SignedWith($this->configuration->signer(), $this->getVerificationKey())
        );
    }

    public function encode(array $payload): string
    {
        $builder = $this->configuration->builder();

        foreach ($payload as $key => $claim) {
            $builder = match ($key) {
                RegisteredClaims::AUDIENCE => $builder->permittedFor(...is_array($claim) ? $claim : [$claim]),
                RegisteredClaims::ID => $builder->identifiedBy((string) $claim),
                RegisteredClaims::ISSUER => $builder->issuedBy((string) $claim),
                RegisteredClaims::SUBJECT => $builder->relatedTo((string) $claim),
                RegisteredClaims::EXPIRATION_TIME => $builder->expiresAt(DateTimeImmutable::createFromFormat('U', (string) $claim)),
                RegisteredClaims::ISSUED_AT => $builder->issuedAt(DateTimeImmutable::createFromFormat('U', (string) $claim)),
                RegisteredClaims::NOT_BEFORE => $builder->canOnlyBeUsedAfter(DateTimeImmutable::createFromFormat('U', (string) $claim)),
                default => $builder->withClaim($key, $claim),
            };
        }

        $token = $builder->getToken($this->configuration->signer(), $this->configuration->signingKey());

        return $token->toString();
    }

    public function decode(string $token): array
    {
        $parser = $this->configuration->parser();

        try {
            $token = $parser->parse($token);
        } catch (CannotDecodeContent|InvalidTokenStructure|UnsupportedHeaderFound $e) {
            throw new TokenInvalidException('Could not decode token: ' . $e->getMessage(), $e->getCode(), $e);
        }

        if (! $this->configuration->validator()->validate($token, ...$this->configuration->validationConstraints())) {
            throw new TokenInvalidException('Token Signature could not be verified.');
        }

        $payload = [];
        foreach ($token->claims()->all() as $key => $claim) {
            if ($claim instanceof DateTimeImmutable) {
                $payload[$key] = $claim->getTimestamp();
            } else {
                $payload[$key] = $claim;
            }
        }

        return $payload;
    }

    private function getSigner(): Signer
    {
        if (! array_key_exists($this->algo, $this->signers)) {
            throw new JwtException('The given algorithm could not be found');
        }
        return new $this->signers[$this->algo]();
    }

    private function isAsymmetric()
    {
        return $this->asymmetric[$this->algo];
    }

    private function getSigningKey(): InMemory
    {
        return InMemory::plainText($this->getPrivate(), $this->getPassphrase());
    }

    private function getPrivate()
    {
        return Arr::get($this->keys, 'private');
    }

    private function getPassphrase()
    {
        return Arr::get($this->keys, 'passphrase');
    }

    private function getVerificationKey(): InMemory
    {
        return $this->isAsymmetric() ? InMemory::plainText($this->getPublicKey()) : InMemory::plainText($this->getSecret());
    }

    private function getPublicKey()
    {
        return Arr::get($this->keys, 'public');
    }

    private function getSecret(): string
    {
        return $this->secret;
    }
}
