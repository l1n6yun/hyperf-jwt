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

namespace L1n6yun\HyperfJwt\Commands;

use Hyperf\Command\Annotation\Command;
use Hyperf\Stringable\Str;

#[Command]
class GenJwtKeypairCommand extends AbstractGenCommand
{
    protected ?string $name = 'gen:jwt-keypair';

    protected string $description = 'Set the JWT private key and public key used to sign the tokens';

    protected array $configs = [
        'RS256' => ['private_key_type' => OPENSSL_KEYTYPE_RSA, 'digest_alg' => 'SHA256', 'private_key_bits' => 4096],
        'RS384' => ['private_key_type' => OPENSSL_KEYTYPE_RSA, 'digest_alg' => 'SHA384', 'private_key_bits' => 4096],
        'RS512' => ['private_key_type' => OPENSSL_KEYTYPE_RSA, 'digest_alg' => 'SHA512', 'private_key_bits' => 4096],
        'ES256' => ['private_key_type' => OPENSSL_KEYTYPE_EC, 'digest_alg' => 'SHA256', 'curve_name' => 'secp256k1'],
        'ES384' => ['private_key_type' => OPENSSL_KEYTYPE_EC, 'digest_alg' => 'SHA384', 'curve_name' => 'secp384r1'],
        'ES512' => ['private_key_type' => OPENSSL_KEYTYPE_EC, 'digest_alg' => 'SHA512', 'curve_name' => 'secp521r1'],
    ];

    public function handle(): void
    {
        [, $config] = $this->choiceAlgorithm();
        $passphrase = $this->setPassphrase();

        [$privateKey, $publicKey] = $this->generateKeypair($config, $passphrase);

        if (! empty($passphrase)) {
            $passphrase = base64_encode($passphrase);
        }

        if ($this->getOption('show')) {
            $this->displayKey($privateKey, $publicKey, $passphrase);
            return;
        }

        if (file_exists($path = $this->envFilePath()) === false) {
            $this->displayKey($privateKey, $publicKey, $passphrase);
            return;
        }

        if (Str::contains(file_get_contents($path), ['JWT_PRIVATE_KEY', 'JWT_PUBLIC_KEY', 'JWT_PASSPHRASE'])) {
            if ($this->getOption('always-no')) {
                $this->comment('The key pair or some part of it already exists. Skipping...');
                return;
            }

            if ($this->isConfirmed() === false) {
                $this->comment('Phew... No changes were made to your key pair.');
                return;
            }

            $force = true;
        } else {
            $force = false;
        }

        foreach (['privateKey', 'publicKey', 'passphrase'] as $name) {
            $this->writeEnv($path, $name, ${$name}, $force);
        }

        $this->info('JWT key pair set successfully.');
    }

    protected function writeEnv(string $path, string $name, ?string $value, bool $force): void
    {
        $envKey = 'JWT_' . Str::upper(Str::snake($name));
        $envValue = empty($value) ? '(null)' : '"' . str_replace("\n", '\n', $value) . '"';

        if (Str::contains(file_get_contents($path), $envKey) === false) {
            file_put_contents($path, "{$envKey}={$envValue}\n", FILE_APPEND);
        } elseif ($force) {
            file_put_contents($path, preg_replace(
                "~\n{$envKey}=[^\n]*~",
                "\n{$envKey}={$envValue}",
                file_get_contents($path)
            ));
        }
    }

    protected function choiceAlgorithm(): array
    {
        $algo = $this->choice('Select algorithm', array_keys($this->configs));
        return [$algo, $this->configs[$algo]];
    }

    protected function setPassphrase(): ?string
    {
        $random = $this->choice('Use random passphrase', ['Yes', 'No']);
        if ($random === 'Yes') {
            return random_bytes(16);
        }
        return $this->ask('Set passphrase (can be empty)');
    }

    protected function generateKeypair(array $config, ?string $passphrase = null): array
    {
        $res = openssl_pkey_new($config);
        openssl_pkey_export($res, $privateKey, $passphrase);
        $publicKey = openssl_pkey_get_details($res)['key'];
        return [$privateKey, $publicKey];
    }

    protected function isConfirmed(): bool
    {
        return $this->getOption('force') ? true : $this->confirm(
            'Are you sure you want to override the key pair? This will invalidate all existing tokens.'
        );
    }

    protected function displayKey(string $privateKey, string $publicKey, ?string $passphrase): void
    {
        $this->info('Private Key:');
        $this->comment($privateKey);
        $this->info('Public Key:');
        $this->comment($publicKey);
        $this->info('Passphrase (base64 encoded):');
        $this->comment(empty($passphrase) ? '<info>No Passphrase</info>' : $passphrase);
    }
}
