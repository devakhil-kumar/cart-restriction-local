<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use App\Helpers\ShopStorage;

class ProxyController extends Controller
{
    public function handle(Request $request)
    {
        Log::info('Proxy hit', $request->all());

        if (!$this->validateSignature($request->all(), $request->get('signature'))) {
            Log::error('Invalid app proxy signature', $request->all());
            return response()->json(['error' => 'Invalid app proxy signature'], 403);
        }

        $shop = $request->get('shop');
        $variantIds = explode(',', $request->get('variant_ids', ''));
        
        if (!$shop || empty($variantIds)) {
            Log::error('Missing shop or variant_ids');
            return response()->json(['error' => 'Missing shop or variant_ids'], 400);
        }

        $accessToken = $this->getShopToken($shop);
        if (!$accessToken) {
            Log::error('Access token not found for shop', ['shop' => $shop]);
            return response()->json(['error' => 'Access token not found'], 403);
        }

        try {
            $locationsResp = Http::withHeaders([
                'X-Shopify-Access-Token' => $accessToken
            ])->get("https://{$shop}/admin/api/2024-04/locations.json");

            if (!$locationsResp->successful()) {
                Log::error('Failed to fetch locations', [
                    'shop' => $shop,
                    'status' => $locationsResp->status(),
                    'response' => $locationsResp->body()
                ]);
                return response()->json(['error' => 'Failed to fetch locations'], 500);
            }

            // Location name to country mapping
            $countryMapping = [
                'NL' => 'Netherlands',
                'BROOK STREET' => 'UK',
                'UK' => 'UK',
                'US' => 'USA',
                'NY' => 'USA',
                'DE' => 'Germany',
            ];

            // Clean and map location name + country
            $locationMap = collect($locationsResp['locations'] ?? [])
                ->mapWithKeys(function ($loc) use ($countryMapping) {
                    $cleanName = preg_replace('/^\d+\s*\|\s*/', '', $loc['name']);
                    $country = 'Unknown';

                    foreach ($countryMapping as $keyword => $mappedCountry) {
                        if (stripos($cleanName, $keyword) !== false) {
                            $country = $mappedCountry;
                            break;
                        }
                    }

                    return [$loc['id'] => [
                        'name' => $cleanName,
                        'country' => $country
                    ]];
                })
                ->toArray();

            $conflicts = [];
            $hasMultiLocationProducts = false;
            $allProductLocations = [];

            foreach ($variantIds as $variantId) {
                if (empty(trim($variantId))) {
                    continue; // Skip empty variant IDs
                }

                $variantResp = Http::withHeaders([
                    'X-Shopify-Access-Token' => $accessToken
                ])->get("https://{$shop}/admin/api/2024-04/variants/{$variantId}.json");

                if (!$variantResp->successful()) {
                    Log::error('Failed to fetch variant', [
                        'variant_id' => $variantId,
                        'status' => $variantResp->status(),
                        'response' => $variantResp->body()
                    ]);
                    continue;
                }

                $variant = $variantResp['variant'];

                // Fetch product
                $productResp = Http::withHeaders([
                    'X-Shopify-Access-Token' => $accessToken
                ])->get("https://{$shop}/admin/api/2024-04/products/{$variant['product_id']}.json");

                if (!$productResp->successful()) {
                    Log::error('Failed to fetch product', [
                        'product_id' => $variant['product_id'],
                        'status' => $productResp->status()
                    ]);
                    continue;
                }

                $productTitle = $productResp['product']['title'] ?? 'Product';
                $rawTitle = $variant['title'];
                $exploded = explode(' / ', $rawTitle);
                $size = trim($exploded[0]);
                $sku = $variant['sku'];

                // Fetch ALL inventory levels for this variant
                $inventoryResp = Http::withHeaders([
                    'X-Shopify-Access-Token' => $accessToken
                ])->get("https://{$shop}/admin/api/2024-04/inventory_levels.json", [
                    'inventory_item_ids' => $variant['inventory_item_id']
                ]);

                if (!$inventoryResp->successful()) {
                    Log::error('Failed to fetch inventory levels', [
                        'inventory_item_id' => $variant['inventory_item_id'],
                        'status' => $inventoryResp->status()
                    ]);
                    continue;
                }

                $levels = $inventoryResp['inventory_levels'];
                $productLocations = [];
                $productLocationNames = [];

                // Check all inventory levels for this product
                foreach ($levels as $level) {
                    // Only consider locations with available inventory
                    if (isset($level['available']) && $level['available'] > 0) {
                        $locationId = $level['location_id'];
                        $locationInfo = $locationMap[$locationId] ?? ['name' => 'Unknown', 'country' => 'Unknown'];
                        
                        $productLocations[] = $locationId;
                        $productLocationNames[] = $locationInfo['country'];
                    }
                }

                // Remove duplicates
                $productLocations = array_unique($productLocations);
                $productLocationNames = array_unique($productLocationNames);

                // Check if this product is available in multiple locations
                if (count($productLocations) > 1) {
                    $hasMultiLocationProducts = true;
                    
                    $conflicts[] = [
                        'name' => "{$productTitle} - {$variant['title']} / {$variant['sku']}",
                        'locations' => $productLocationNames,
                        'shipping_countries' => $productLocationNames,
                        'sku' => $variant['sku'] ?? '',
                        'size' => $size,
                        'reason' => 'Product available in multiple locations: ' . implode(', ', $productLocationNames)
                    ];

                    Log::warning('Product found in multiple locations', [
                        'variant_id' => $variantId,
                        'product_title' => $productTitle,
                        'locations' => $productLocationNames,
                        'location_count' => count($productLocations)
                    ]);
                } else {
                    // Single location product
                    if (!empty($productLocations)) {
                        $locationInfo = $locationMap[$productLocations[0]] ?? ['name' => 'Unknown', 'country' => 'Unknown'];
                        $allProductLocations[] = $productLocations[0];
                        
                        $conflicts[] = [
                            'name' => "{$productTitle} - {$variant['title']} / {$variant['sku']}",
                            'location' => $locationInfo['name'],
                            'shipping_country' => $locationInfo['country'],
                            'sku' => $variant['sku'] ?? '',
                            'size' => $size,
                            'reason' => 'Single location: ' . $locationInfo['country']
                        ];
                    }
                }
            }

            // Check if products from different single locations exist
            $uniqueSingleLocations = array_unique($allProductLocations);
            $hasDifferentSingleLocations = count($uniqueSingleLocations) > 1;

            // Determine if checkout should be allowed
            $allowCheckout = !$hasMultiLocationProducts && !$hasDifferentSingleLocations;

            $response = [
                'allow_checkout' => $allowCheckout,
                'conflicts' => $conflicts
            ];

            // Add detailed reasoning
            if ($hasMultiLocationProducts) {
                $response['reason'] = 'Some products are available in multiple locations';
                $response['conflict_type'] = 'multi_location_products';
            } elseif ($hasDifferentSingleLocations) {
                $response['reason'] = 'Products are from different single locations';
                $response['conflict_type'] = 'different_single_locations';
                $response['locations'] = $uniqueSingleLocations;
            } else {
                $response['reason'] = 'All products are from the same single location';
                $response['conflict_type'] = 'none';
            }

            Log::info('Cart check completed', [
                'shop' => $shop,
                'variant_ids' => $variantIds,
                'allow_checkout' => $allowCheckout,
                'has_multi_location_products' => $hasMultiLocationProducts,
                'has_different_single_locations' => $hasDifferentSingleLocations,
                'unique_single_locations' => count($uniqueSingleLocations),
                'reason' => $response['reason']
            ]);

            return response()->json($response);

        } catch (\Exception $e) {
            Log::error('Proxy handler exception', [
                'shop' => $shop,
                'exception' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            return response()->json(['error' => 'Internal server error'], 500);
        }
    }

    /**
     * Validate signatures from Shopify
     * Returns: boolean (true if valid, false if invalid)
     */
    private function validateSignature($params, $signature)
    {
        if (!$signature) {
            Log::warning('No signature provided');
            return false;
        }

        $shared_secret = config('shopify.api_secret');
        $params = request()->all();
        
        if (!isset($params['logged_in_customer_id'])) {
            $params['logged_in_customer_id'] = "";
        }

        $params = array_diff_key($params, array('signature' => ''));
        ksort($params);
        $params = str_replace("%2F", "/", http_build_query($params));
        $params = str_replace("&", "", $params);
        $params = str_replace("%2C", ",", $params);
        $computed_hmac = hash_hmac('sha256', $params, $shared_secret);
        
        return hash_equals($signature, $computed_hmac);
    }

    /**
     * Get access token for shop from database
     */
    private function getShopToken($shop)
    {
        try {
            // ShopStorage::get() now returns the decrypted token directly
            $accessToken = ShopStorage::get($shop);
            
            if (!$accessToken) {
                Log::error("No access token found for shop: {$shop}");
                return null;
            }

            return $accessToken;
            
        } catch (\Exception $e) {
            Log::error("Error getting shop token for {$shop}: " . $e->getMessage());
            return null;
        }
    }
}