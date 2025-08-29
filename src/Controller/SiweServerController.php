<?php

namespace Drupal\siwe_server\Controller;

use Drupal\Core\Controller\ControllerBase;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Drupal\siwe_server\Service\JwtService;

/**
 * Controller for SIWE server endpoints.
 */
class SiweServerController extends ControllerBase {

  protected $jwtService;

  public function __construct(JwtService $jwt_service) {
    $this->jwtService = $jwt_service;
  }

  public static function create(ContainerInterface $container) {
    return new static(
      $container->get('siwe_server.jwt_service')
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
      $cache_key = 'siwe_nonce:' . $this->getClientIdentifier($request);
      \Drupal::cache()->set($cache_key, $nonce, time() + 300);

      // Also store a reverse lookup to validate the nonce itself
      $nonce_key = 'siwe_nonce_lookup:' . $nonce;
      \Drupal::cache()->set($nonce_key, $this->getClientIdentifier($request), time() + 300);

      return new JsonResponse(['nonce' => $nonce]);
    }
    catch (\Exception $e) {
      return new JsonResponse(['error' => 'Failed to generate nonce'], 500);
    }
  }

  /**
   * Refreshes an access token.
   */
  public function refresh(Request $request): JsonResponse {
    try {
      $content = json_decode($request->getContent(), TRUE);
      $refresh_token = $content['refresh_token'] ?? '';

      if (empty($refresh_token)) {
        return new JsonResponse(['error' => 'Refresh token is required'], 400);
      }

      $tokens = $this->jwtService->refreshAccessToken($refresh_token);

      if (!$tokens) {
        return new JsonResponse(['error' => 'Invalid refresh token'], 401);
      }

      return new JsonResponse($tokens);
    }
    catch (\Exception $e) {
      return new JsonResponse(['error' => 'Failed to refresh token'], 500);
    }
  }

  /**
   * Logs out the user.
   */
  public function logout(Request $request): JsonResponse {
    // In a JWT-based system, logout is typically handled client-side
    // by deleting the tokens. However, we can still invalidate
    // refresh tokens on the server side if we're storing them.
    return new JsonResponse(['message' => 'Logged out successfully']);
  }

  /**
   * Generates a unique client identifier.
   */
  private function getClientIdentifier(Request $request): string {
    $ip = $request->getClientIp() ?: 'unknown';
    $user_agent = $request->headers->get('User-Agent', 'unknown');
    $origin = $request->headers->get('Origin', 'unknown');

    // Create a unique identifier based on client characteristics
    return hash('sha256', $ip . '|' . $user_agent . '|' . $origin);
  }
}