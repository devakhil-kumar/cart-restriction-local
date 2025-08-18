<?php

return [
    /*
    |--------------------------------------------------------------------------
    | Shopify API Configuration
    |--------------------------------------------------------------------------
    |
    | Configuration for Shopify API integration
    |
    */

    'api_key' => env('SHOPIFY_API_KEY'),
    'api_secret' => env('SHOPIFY_API_SECRET_KEY'),
    'scopes' => env('SHOPIFY_SCOPES', 'read_products,read_inventory,read_locations,read_script_tags,write_script_tags,read_customers,write_customers'),
    'redirect_uri' => env('APP_URL') . '/shopify/callback',
    
    /*
    |--------------------------------------------------------------------------
    | API Version
    |--------------------------------------------------------------------------
    |
    | The Shopify API version to use for requests
    |
    */
    'api_version' => env('SHOPIFY_API_VERSION', '2024-04'),
    
    /*
    |--------------------------------------------------------------------------
    | Script Settings
    |--------------------------------------------------------------------------
    |
    | Settings for script tag injection
    |
    */
    'scripts' => [
        'cart_check' => [
            'path' => '/cart-check.js',
            'event' => 'onload'
        ]
    ],
    
    /*
    |--------------------------------------------------------------------------
    | App Settings
    |--------------------------------------------------------------------------
    |
    | General app configuration
    |
    */
    'app_name' => env('APP_NAME', 'Cart Check App'),
    'app_url' => env('APP_URL'),
];