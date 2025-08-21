<?php

namespace App\Helpers;

use App\Models\Shop;
use Illuminate\Support\Facades\Log;

class ShopStorage
{
    /**
     * Get all shops from database
     */
    public static function getAllShops()
    {
        try {
            return Shop::all()->pluck('access_token', 'shop_domain')->toArray();
        } catch (\Exception $e) {
            Log::error('Error getting all shops: ' . $e->getMessage());
            return [];
        }
    }

    /**
     * Get access token for a specific shop
     */
    public static function get($shopDomain)
    {
        try {
            $shop = Shop::findByDomain($shopDomain);

            echo"<pre>"; print_r($shop);  die;

            return $shop ? $shop->access_token : null;
        } catch (\Exception $e) {
            Log::error("Error getting shop {$shopDomain}: " . $e->getMessage());
            return null;
        }
    }

    /**
     * Store or update shop access token
     */
    public static function set($shopDomain, $accessToken, $settings = null)
    {
        try {
            Shop::createOrUpdateShop($shopDomain, $accessToken, $settings);
            Log::info("Shop {$shopDomain} stored/updated successfully");
            return true;
        } catch (\Exception $e) {
            Log::error("Error storing shop {$shopDomain}: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Delete shop from database
     */
    public static function delete($shopDomain)
    {
        try {
            $deleted = Shop::where('shop_domain', $shopDomain)->delete();
            if ($deleted) {
                Log::info("Shop {$shopDomain} deleted successfully");
            }
            return $deleted > 0;
        } catch (\Exception $e) {
            Log::error("Error deleting shop {$shopDomain}: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Check if shop exists
     */
    public static function exists($shopDomain)
    {
        try {
            return Shop::shopExists($shopDomain);
        } catch (\Exception $e) {
            Log::error("Error checking if shop {$shopDomain} exists: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Decrypt token (now handled automatically by model cast)
     */
    public static function decryptToken($encryptedToken)
    {
        // With the encrypted cast, the token is automatically decrypted
        return $encryptedToken;
    }

    /**
     * Get shop model instance
     */
    public static function getShop($shopDomain)
    {
        try {
            return Shop::findByDomain($shopDomain);
        } catch (\Exception $e) {
            Log::error("Error getting shop model {$shopDomain}: " . $e->getMessage());
            return null;
        }
    }

    /**
     * Get shop settings
     */
    public static function getSettings($shopDomain, $key = null, $default = null)
    {
        try {
            $shop = Shop::findByDomain($shopDomain);
            return $shop ? $shop->getSettings($key, $default) : $default;
        } catch (\Exception $e) {
            Log::error("Error getting settings for shop {$shopDomain}: " . $e->getMessage());
            return $default;
        }
    }

    /**
     * Update shop settings
     */
    public static function updateSettings($shopDomain, $key, $value = null)
    {
        try {
            $shop = Shop::findByDomain($shopDomain);
            if ($shop) {
                $shop->updateSettings($key, $value);
                return true;
            }
            return false;
        } catch (\Exception $e) {
            Log::error("Error updating settings for shop {$shopDomain}: " . $e->getMessage());
            return false;
        }
    }
}