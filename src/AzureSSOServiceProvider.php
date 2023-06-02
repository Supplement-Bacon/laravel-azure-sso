<?php

namespace SupplementBacon\AzureSSO;

use Illuminate\Foundation\Console\AboutCommand;
use Illuminate\Support\ServiceProvider;

class InseeServiceProvider extends ServiceProvider
{
    /**
     * Bootstrap services.
     *
     * @return void
     */
    public function boot()
    {
        $configPath = __DIR__ . '/../config/azure-sso.php';

        $this->publishes([$configPath => config_path('azure-sso.php')], 'azure-sso-config');
        $this->mergeConfigFrom($configPath, 'azure-sso');

        if ($this->app instanceof Laravel\Lumen\Application) {
            $this->app->configure('azure-sso');
        }

        AboutCommand::add('Laravel Azure SSO', fn () => ['Version' => '1.0.0']);

        if (!$this->app->runningInConsole()) {
            return;
        }

        app('router')->aliasMiddleware('azure-jwt', AzureJWTValidate::class);
    }

    /**
     * Register services.
     *
     * @return void
     */
    public function register()
    {
        //
    }

    public function provides()
    {
        return ['azure-sso'];
    }
}
