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
class GenJwtSecretCommand extends AbstractGenCommand
{
    protected ?string $name = 'gen:jwt-secret';

    protected string $description = 'Set the JWT secret key used to sign the tokens';

    public function handle(): void
    {
        $key = base64_encode(random_bytes(64));

        if ($this->getOption('show')) {
            $this->comment($key);
            return;
        }

        if (file_exists($path = $this->envFilePath()) === false) {
            $this->displayKey($key);
            return;
        }

        if (Str::contains(file_get_contents($path), 'JWT_SECRET') === false) {
            file_put_contents($path, "\nJWT_SECRET=\"{$key}\"\n", FILE_APPEND);
        } else {
            if ($this->getOption('always-no')) {
                $this->comment('Secret key already exists. Skipping...');
                return;
            }

            if ($this->isConfirmed() === false) {
                $this->comment('Phew... No changes were made to your secret key.');
                return;
            }

            file_put_contents($path, preg_replace(
                "~\nJWT_SECRET=[^\n]*~",
                "\nJWT_SECRET=\"{$key}\"",
                file_get_contents($path)
            ));
        }

        $this->displayKey($key);
    }

    protected function displayKey(string $key): void
    {
        $this->info("JWT secret [<comment>{$key}</comment>] (base64 encoded) set successfully.");
    }

    private function isConfirmed(): ?bool
    {
        return $this->getOption('force') ? true : $this->confirm(
            'Are you sure you want to override the key pair? This will invalidate all existing tokens.'
        );
    }
}
