<?php

namespace Drupal\siwe_server\Controller;

use Drupal\Core\Cache\CacheBackendInterface;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Controller\ControllerBase;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;

/**
 * Controller for SIWE server endpoints.
 */
class SiweServerController extends ControllerBase {

  /**
   * The cache backend.
   *
   * @var \Drupal\Core\Cache\CacheBackendInterface
   */
  protected CacheBackendInterface $cache;

  /**
   * Constructs the SiweServerController object.
   *
   * @param \Drupal\Core\Config\ConfigFactoryInterface $config_factory
   *   The config factory.
   * @param \Drupal\Core\Cache\CacheBackendInterface $cache_backend
   *   The cache backend.
   */
  public function __construct(ConfigFactoryInterface $config_factory, CacheBackendInterface $cache_backend) {
    $this->configFactory = $config_factory;
    $this->cache = $cache_backend;
  }

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container) {
    return new static(
      $container->get('config.factory'),
      $container->get('cache.default')
    );
  }

  /**
   * Generates a nonce for SIWE.
   */
  public function getNonce(Request $request): JsonResponse {
    try {
      // Generate a cryptographically secure random nonce.
      $nonce = bin2hex(random_bytes(16));

      // Store nonce in cache with a 5-minute TTL (300 seconds)
      $ttl = $this->configFactory->get('siwe_login.settings')->get('nonce_ttl') ?: 300;
      $cache_key = 'siwe_nonce:' . $this->getClientIdentifier($request);
      $this->cache->set($cache_key, $nonce, time() + $ttl);

      // Also store a reverse lookup to validate the nonce itself.
      $nonce_key = 'siwe_nonce_lookup:' . $nonce;
      $this->cache->set($nonce_key, $this->getClientIdentifier($request), time() + 300);

      return new JsonResponse(['nonce' => $nonce]);
    }
    catch (\Exception $e) {
      return new JsonResponse(['error' => 'Failed to generate nonce'], 500);
    }
  }

  /**
   * Logs out the user.
   */
  public function logout(Request $request): JsonResponse {
    // In a JWT-based system, logout is typically handled client-side
    // by deleting the tokens.
    return new JsonResponse(['message' => 'Logged out successfully']);
  }

  /**
   * Generates a unique client identifier.
   */
  private function getClientIdentifier(Request $request): string {
    $ip = $request->getClientIp() ?: 'unknown';
    $user_agent = $request->headers->get('User-Agent', 'unknown');
    $origin = $request->headers->get('Origin', 'unknown');

    // Create a unique identifier based on client characteristics.
    return hash('sha256', $ip . '|' . $user_agent . '|' . $origin);
  }

}
