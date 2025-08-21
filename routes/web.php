<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\ShopifyController;
use App\Http\Controllers\ProxyController;
use App\Helpers\ShopStorage;
use Illuminate\Support\Facades\Request;
use Illuminate\Support\Facades\Artisan;
use App\Models\Shop;

Route::delete('/shop/{shop}', function ($shopDomain, Request $request) {
    $shop = Shop::findByDomain($shopDomain);

    if ($shop) {
        $shop->delete();
        return redirect('/')->with('status', 'Shop data deleted successfully!');
    }

    return redirect('/')->with('error', 'Shop not found.');
})->name('shop.delete');

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
Route::get('/shopify/install', [ShopifyController::class, 'install'])->name('shopify.install');
Route::get('/shopify/callback', [ShopifyController::class, 'callback'])->name('shopify.callback');

// Uninstall webhook (optional)
Route::post('/shopify/uninstall', [ShopifyController::class, 'uninstall'])->name('shopify.uninstall');

// App proxy handler
Route::get('/proxy-handler-local', [ProxyController::class, 'handle'])->name('shopify.proxy');

Route::get('/', function (Request $request) {
    $shop = request()->get('shop'); // Get ?shop= param if passed

    if (!$shop) {
        return view('welcome');
    }

    try {
        // Check if shop exists and has valid access token
        $shopModel = ShopStorage::getShop($shop);
        
        if ($shopModel && $shopModel->access_token) {
            return view('shopify.dashboard', [
                'shop' => $shop,
                'installed_at' => $shopModel->installed_at
            ]);
        } else {
            return view('shopify.not_installed', ['shop' => $shop]);
        }
        
    } catch (\Exception $e) {
        \Log::error('Error checking shop status', [
            'shop' => $shop,
            'error' => $e->getMessage()
        ]);
        
        return view('shopify.not_installed', ['shop' => $shop]);
    }
})->name('shopify.home');