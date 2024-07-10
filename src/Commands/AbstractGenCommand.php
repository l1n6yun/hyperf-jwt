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

use Hyperf\Command\Command as HyperfCommand;
use Symfony\Component\Console\Input\InputOption;

abstract class AbstractGenCommand extends HyperfCommand
{
    protected function configure(): void
    {
        parent::configure();
        $this->setDescription($this->description);
        $this->addOption('show', 's', InputOption::VALUE_NONE, 'Display the key instead of modifying files');
        $this->addOption('always-no', null, InputOption::VALUE_NONE, 'Skip generating key if it already exists');
        $this->addOption('force', 'f', InputOption::VALUE_NONE, 'Skip confirmation when overwriting an existing key');
    }

    protected function envFilePath(): string
    {
        return BASE_PATH . '/.env';
    }

    protected function getOption(string $name, $default = null)
    {
        $result = $this->input->getOption($name);
        return empty($result) ? $default : $result;
    }
}
