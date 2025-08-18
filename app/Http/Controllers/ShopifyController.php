<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use App\Jobs\InjectScriptTagToShop;
use App\Helpers\ShopStorage;

class ShopifyController extends Controller
{
    public function install(Request $request)
    {
        $shop = $request->get('shop');
        
        if (!$shop) {
            Log::error('Shop parameter missing in install request');
            return redirect()->back()->with('error', 'Shop parameter is required');
        }

        $scopes = 'read_products,read_inventory,read_locations,read_script_tags,write_script_tags,read_customers,write_customers';
        $redirectUri = urlencode(env('APP_URL') . '/shopify/callback');
        $apiKey = config('shopify.api_key');
        $installUrl = "https://{$shop}/admin/oauth/authorize?client_id={$apiKey}&scope={$scopes}&redirect_uri={$redirectUri}&state=123&grant_options[]=per-user";
        
        Log::info("Redirecting to Shopify install URL for shop: {$shop}");
        return redirect($installUrl);
    }

    public function callback(Request $request)
    {
        Log::info('Shopify callback received', $request->all());

        if (!$this->validateHmac($request->all(), $request->get('hmac'))) {
            Log::error('Invalid HMAC in callback', $request->all());
            abort(403, 'Invalid HMAC');
        }

        $shop = $request->get('shop');
        $code = $request->get('code');
        $apiSecret = config('shopify.api_secret');
        $apiKey = config('shopify.api_key');

        if (!$shop || !$code) {
            Log::error('Missing shop or code in callback', $request->all());
            abort(400, 'Missing required parameters');
        }

        try {
            // Exchange code for access token
            $response = Http::post("https://{$shop}/admin/oauth/access_token", [
                'client_id' => $apiKey,
                'client_secret' => $apiSecret,
                'code' => $code,
            ]);

            if (!$response->successful() || !isset($response['access_token'])) {
                Log::error('Failed to get access token from Shopify', [
                    'shop' => $shop,
                    'response' => $response->json()
                ]);
                abort(500, 'Failed to authenticate with Shopify');
            }

            $accessToken = $response['access_token'];
            
            // Store in SQLite database
            $stored = ShopStorage::set($shop, $accessToken);
            
            if (!$stored) {
                Log::error('Failed to store access token in database', ['shop' => $shop]);
                abort(500, 'Failed to store authentication data');
            }

            // Set session data
            session(['shop' => $shop, 'access_token' => $accessToken]);

            // Inject ScriptTag with APP_URL (job will get token from database)
            InjectScriptTagToShop::dispatch($shop);

            Log::info("Shop {$shop} installed successfully");

            return view('shopify.installed', ['shop' => $shop]);

        } catch (\Exception $e) {
            Log::error('Exception during Shopify callback', [
                'shop' => $shop,
                'error' => $e->getMessage()
            ]);
            abort(500, 'Installation failed');
        }
    }

    private function validateHmac($params, $hmac)
    {
        if (!$hmac) {
            return false;
        }

        unset($params['hmac'], $params['signature']);
        ksort($params);
        $computedHmac = hash_hmac('sha256', http_build_query($params), config('shopify.api_secret'));
        
        return hash_equals($computedHmac, $hmac);
    }

    /**
     * Uninstall webhook handler (optional)
     */
    public function uninstall(Request $request)
    {
        $shop = $request->header('X-Shopify-Shop-Domain');
        
        if ($shop) {
            ShopStorage::delete($shop);
            Log::info("Shop {$shop} uninstalled and removed from database");
        }

        return response()->json(['status' => 'success']);
    }
}