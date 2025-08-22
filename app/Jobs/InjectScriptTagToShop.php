<?php

namespace App\Jobs;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use App\Helpers\ShopStorage;

class InjectScriptTagToShop implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    protected $shopDomain;
    protected $accessToken;

    /**
     * Create a new job instance.
     */
    public function __construct($shopDomain, $accessToken = null)
    {
        $this->shopDomain = $shopDomain;
        $this->accessToken = $accessToken;
    }

    /**
     * Execute the job.
     */
    public function handle()
    {
        $accessToken = ShopStorage::get($this->shopDomain);
        
        if (!$accessToken) {
            Log::error("Access token not found for shop: {$this->shopDomain}");
            throw new \Exception("Access token not found for shop: {$this->shopDomain}");
        }

        $scripts = ['/cart-check.js'];

        foreach ($scripts as $scriptPath) {
            $scriptUrl = rtrim(env('APP_URL'), '/') . $scriptPath;
            
            try {
                Log::info("Starting script injection for shop: {$this->shopDomain}", [
                    'script_url' => $scriptUrl
                ]);

                // Remove existing ScriptTag with same src (optional cleanup)
                $this->removeExistingScriptTag($accessToken, $scriptUrl);

                // Inject new ScriptTag
                $this->injectNewScriptTag($accessToken, $scriptUrl);

            } catch (\Exception $e) {
                Log::error("ScriptTag injection failed", [
                    'shop' => $this->shopDomain,
                    'script' => $scriptUrl,
                    'error' => $e->getMessage(),
                    'trace' => $e->getTraceAsString()
                ]);

                throw $e; // Will be retried by queue system
            }
        }

        Log::info("Script injection completed successfully for shop: {$this->shopDomain}");
    }

    /**
     * Remove existing script tag with same URL
     */
    private function removeExistingScriptTag($accessToken, $scriptUrl)
    {
        try {
            $existing = Http::withHeaders([
                'X-Shopify-Access-Token' => $accessToken
            ])->get("https://{$this->shopDomain}/admin/api/2024-04/script_tags.json");

            if ($existing->failed()) {
                Log::warning("Failed to fetch existing script tags", [
                    'shop' => $this->shopDomain,
                    'status' => $existing->status(),
                    'response' => $existing->body()
                ]);
                return;
            }

            $scriptTags = $existing->json('script_tags', []);
            $removedCount = 0;

            foreach ($scriptTags as $tag) {
                if (isset($tag['src']) && $tag['src'] === $scriptUrl) {
                    $deleteResponse = Http::withHeaders([
                        'X-Shopify-Access-Token' => $accessToken
                    ])->delete("https://{$this->shopDomain}/admin/api/2024-04/script_tags/{$tag['id']}.json");

                    if ($deleteResponse->successful()) {
                        $removedCount++;
                        Log::info("Removed existing script tag", [
                            'shop' => $this->shopDomain,
                            'script_tag_id' => $tag['id'],
                            'src' => $scriptUrl
                        ]);
                    } else {
                        Log::warning("Failed to remove existing script tag", [
                            'shop' => $this->shopDomain,
                            'script_tag_id' => $tag['id'],
                            'status' => $deleteResponse->status(),
                            'response' => $deleteResponse->body()
                        ]);
                    }
                }
            }

            if ($removedCount > 0) {
                Log::info("Removed {$removedCount} existing script tag(s) for shop: {$this->shopDomain}");
            }

        } catch (\Exception $e) {
            Log::warning("Exception while removing existing script tags", [
                'shop' => $this->shopDomain,
                'error' => $e->getMessage()
            ]);
            // Don't throw here - continue with injection even if cleanup fails
        }
    }

    /**
     * Inject new script tag
     */
    private function injectNewScriptTag($accessToken, $scriptUrl)
    {
        $response = Http::withHeaders([
            'X-Shopify-Access-Token' => $accessToken,
            'Content-Type' => 'application/json'
        ])->post("https://{$this->shopDomain}/admin/api/2024-04/script_tags.json", [
            'script_tag' => [
                'event' => 'onload',
                'src' => $scriptUrl,
            ]
        ]);

        if ($response->successful()) {
            $scriptTag = $response->json('script_tag', []);
            Log::info("ScriptTag injected successfully", [
                'shop' => $this->shopDomain,
                'script_url' => $scriptUrl,
                'script_tag_id' => $scriptTag['id'] ?? 'unknown',
                'created_at' => $scriptTag['created_at'] ?? null
            ]);
        } else {
            $errorMessage = "Failed to inject ScriptTag";
            $responseBody = $response->json();
            
            Log::error($errorMessage, [
                'shop' => $this->shopDomain,
                'script_url' => $scriptUrl,
                'status' => $response->status(),
                'response' => $responseBody,
                'headers' => $response->headers()
            ]);

            // Provide more specific error message based on response
            if ($response->status() === 401) {
                throw new \Exception("Authentication failed - invalid access token for shop: {$this->shopDomain}");
            } elseif ($response->status() === 403) {
                throw new \Exception("Insufficient permissions to create script tags for shop: {$this->shopDomain}");
            } elseif ($response->status() === 422) {
                $errors = $responseBody['errors'] ?? 'Validation failed';
                throw new \Exception("Validation error creating script tag: " . json_encode($errors));
            } else {
                throw new \Exception("{$errorMessage} (HTTP {$response->status()})");
            }
        }
    }

    /**
     * Handle a job failure.
     */
    public function failed(\Throwable $exception)
    {
        Log::error("InjectScriptTagToShop job failed permanently", [
            'shop' => $this->shopDomain,
            'error' => $exception->getMessage(),
            'trace' => $exception->getTraceAsString()
        ]);
    }
}