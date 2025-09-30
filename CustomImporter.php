<?php

namespace Piwik\Plugins\CustomImporter;

class CustomImporter extends \Piwik\Plugin
{
    public function registerCommands($commands)
    {
        $commands[] = new Commands\ImportLogsCommand();
        return $commands;
    }
}


