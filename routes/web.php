<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\ShopifyController;
use App\Http\Controllers\ProxyController;
use App\Helpers\ShopStorage;
use Illuminate\Support\Facades\Request;
use Illuminate\Support\Facades\Artisan;

Route::get('/clear-cache', function () {
    Artisan::call('config:clear');
    Artisan::call('cache:clear');
    Artisan::call('route:clear');
    Artisan::call('view:clear');
    
    return 'Config, cache, route, and view caches cleared!';
});

Route::get('/cart-check.js', function () {
    return response()->view('js.cart-check')->header('Content-Type', 'application/javascript');
});

// OAuth start
Route::get('/shopify/install', [ShopifyController::class, 'install']);
Route::get('/shopify/callback', [ShopifyController::class, 'callback'])->name('shopify.callback');

// App proxy handler
Route::get('/proxy-handler-local', [ProxyController::class, 'handle']);

Route::get('/', function (Request $request) {
    $shop = request()->get('shop'); // Get ?shop= param if passed

    if (!$shop) {
        return view('welcome');
        //return response("Missing shop parameter.", 400);
    }
    $encrypted = ShopStorage::get($shop);
    $accessToken = ShopStorage::decryptToken($encrypted);

    if ($accessToken) {
        return view('shopify.dashboard', ['shop' => $shop]);
    } else {
        return view('shopify.not_installed', ['shop' => $shop]);
    }
})->name('shopify.home');
