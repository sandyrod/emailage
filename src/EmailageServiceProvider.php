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
         $this->mergeConfigFrom(
            __DIR__.'/../config/emailage_config.php',
            'aws'
        );

        $this->app->singleton('sandyrod', function ($app) {
            $config = $app->make('config')->get('sandyrod');

            return new Sdk($config);
        });

        $this->app->alias('sandyrod', 'sandyrod\Emailage');
    }

    /**
     * Bootstrap services.
     *
     * @return void
     */
    public function boot() :void
    {
        if ($this->app instanceof LaravelApplication && $this->app->runningInConsole()) {
            $this->publishes(
                [__DIR__.'/../config/emailage_config.php' => config_path('emailage.php')],
                'emailage-config'
            );
        } elseif ($this->app instanceof LumenApplication) {
            $this->app->configure('emailage');
        }
    }

    /**
     * Get the services provided by the provider.
     *
     * @return array
     */
    public function provides()
    {
        return ['sandyrod', 'sandyrod\Emailage'];
    }

}
