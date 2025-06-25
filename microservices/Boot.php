<?php
namespace Microservices;

use App\Config\Paths;
use App\Modules\Main;
use Dotenv\Dotenv;

class Boot
{
    public static function loadThemAll($paths)
    {
        static::loadConstants($paths);
        static::loadDotEnv($paths);
        static::loadFunction($paths);

        // Ok, here we go!
        (new Main)->run();
    }
    protected static function loadConstants(Paths $paths): void
    {
        require_once $paths->appDirectory . '/Config/Constants.php';
    }

    protected static function loadDotEnv(Paths $paths): void
    {
        $dotenv = Dotenv::createImmutable($paths->appDirectory . '/../');
        $dotenv->load();
    }

    protected static function loadFunction(Paths $paths)
    {
        require_once $paths->appDirectory . '/Helpers/functions.php';
    }
}
