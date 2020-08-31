<?php

namespace sandyrod\emailage;

use Illuminate\Support\ServiceProvider;

class EmailageServiceProvider extends ServiceProvider
{
    /**
     * Register services.
     *
     * @return void
     */
    public function register() :void
    {
         $this->loadRoutesFrom(__DIR__.'/routes.php');
    }

    /**
     * Bootstrap services.
     *
     * @return void
     */
    public function boot() :void
    {

    }

}
