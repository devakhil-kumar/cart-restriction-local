<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Shop extends Model
{
    use HasFactory;

    protected $fillable = [
        'shop_domain',
        'access_token',
        'installed_at',
        'settings'
    ];

    protected $casts = [
        'access_token' => 'encrypted',
        'installed_at' => 'datetime',
        'settings' => 'json'
    ];

    /**
     * Get shop by domain
     */
    public static function findByDomain($domain)
    {
        return self::where('shop_domain', $domain)->first();
    }

    /**
     * Create or update shop
     */
    public static function createOrUpdateShop($domain, $accessToken, $settings = null)
    {
        return self::updateOrCreate(
            ['shop_domain' => $domain],
            [
                'access_token' => $accessToken,
                'installed_at' => now(),
                'settings' => $settings
            ]
        );
    }

    /**
     * Check if shop exists
     */
    public static function shopExists($domain)
    {
        return self::where('shop_domain', $domain)->exists();
    }

    /**
     * Get app settings for shop
     */
    public function getSettings($key = null, $default = null)
    {
        if ($key === null) {
            return $this->settings ?? [];
        }

        return data_get($this->settings, $key, $default);
    }

    /**
     * Update app settings for shop
     */
    public function updateSettings($key, $value = null)
    {
        if (is_array($key)) {
            // Update multiple settings
            $settings = $this->settings ?? [];
            $this->settings = array_merge($settings, $key);
        } else {
            // Update single setting
            $settings = $this->settings ?? [];
            data_set($settings, $key, $value);
            $this->settings = $settings;
        }

        $this->save();
        return $this;
    }
}