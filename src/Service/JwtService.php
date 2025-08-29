<?php

namespace Drupal\siwe_server\Service;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\State\StateInterface;
use Drupal\Core\Logger\LoggerChannelFactoryInterface;
use Drupal\user\UserInterface;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\SignatureInvalidException;

/**
 * Enhanced JWT service that doesn't depend on jwt module.
 */
class JwtService
{

  protected $config;
  protected $state;
  protected $logger;
  protected $privateKey;
  protected $publicKey;
  protected $algorithm = 'RS256';

  public function __construct(
    ConfigFactoryInterface $config_factory,
    StateInterface $state,
    LoggerChannelFactoryInterface $logger_factory
  ) {
    $this->config = $config_factory->get('siwe_server.settings');
    $this->state = $state;
    $this->logger = $logger_factory->get('siwe_server');
    $this->initializeKeys();
  }

  /**
   * Generates access and refresh tokens.
   */
  public function generateTokens(UserInterface $user, array $additional_claims = []): array
  {
    $current_time = time();
    $issued_at = $current_time;

    // Base claims
    $base_claims = [
      'iss' => \Drupal::request()->getSchemeAndHttpHost(),
      'aud' => $this->config->get('jwt_audience') ?: 'drupal-siwe',
      'iat' => $issued_at,
      'sub' => $user->id(),
      'jti' => $this->generateJti(), // JWT ID for tracking
    ];

    // Access token (short-lived)
    $access_claims = array_merge($base_claims, [
      'exp' => $current_time + $this->getAccessTokenTtl(),
      'type' => 'access',
      'uid' => $user->id(),
      'name' => $user->getAccountName(),
      'roles' => array_values($user->getRoles()),
      'address' => $user->get('field_ethereum_address')->value ?? null,
    ], $additional_claims);

    // Refresh token (long-lived)
    $refresh_claims = array_merge($base_claims, [
      'exp' => $current_time + $this->getRefreshTokenTtl(),
      'type' => 'refresh',
      'uid' => $user->id(),
    ]);

    try {
      $access_token = JWT::encode($access_claims, $this->privateKey, $this->algorithm);
      $refresh_token = JWT::encode($refresh_claims, $this->privateKey, $this->algorithm);

      // Store refresh token for validation
      $this->storeRefreshToken($user->id(), $refresh_claims['jti'], $refresh_claims['exp']);

      return [
        'access_token' => $access_token,
        'refresh_token' => $refresh_token,
        'token_type' => 'Bearer',
        'expires_in' => $this->getAccessTokenTtl(),
        'refresh_expires_in' => $this->getRefreshTokenTtl(),
      ];
    } catch (\Exception $e) {
      $this->logger->error('Failed to generate JWT tokens: @message', [
        '@message' => $e->getMessage(),
      ]);
      throw new \RuntimeException('Token generation failed');
    }
  }

  /**
   * Validates a JWT token.
   */
  public function validateToken(string $token, string $expected_type = null): ?array
  {
    try {
      $decoded = JWT::decode($token, new Key($this->publicKey, $this->algorithm));
      $payload = (array) $decoded;

      // Validate token type if specified
      if ($expected_type && ($payload['type'] ?? null) !== $expected_type) {
        $this->logger->warning('Token type mismatch. Expected: @expected, Got: @actual', [
          '@expected' => $expected_type,
          '@actual' => $payload['type'] ?? 'unknown',
        ]);
        return null;
      }

      // Additional validation for refresh tokens
      if (($payload['type'] ?? null) === 'refresh') {
        if (!$this->isRefreshTokenValid($payload['uid'], $payload['jti'])) {
          $this->logger->warning('Refresh token not found in storage or expired');
          return null;
        }
      }

      return $payload;
    } catch (ExpiredException $e) {
      $this->logger->info('Token expired: @message', ['@message' => $e->getMessage()]);
      return null;
    } catch (SignatureInvalidException $e) {
      $this->logger->warning('Invalid token signature: @message', ['@message' => $e->getMessage()]);
      return null;
    } catch (\Exception $e) {
      $this->logger->error('Token validation failed: @message', [
        '@message' => $e->getMessage(),
      ]);
      return null;
    }
  }

  /**
   * Refreshes an access token using a refresh token.
   */
  public function refreshAccessToken(string $refresh_token): ?array
  {
    $payload = $this->validateToken($refresh_token, 'refresh');

    if (!$payload) {
      return null;
    }

    // Load user
    $user = \Drupal::entityTypeManager()
      ->getStorage('user')
      ->load($payload['uid']);

    if (!$user || !$user->isActive()) {
      $this->logger->warning('User not found or inactive during token refresh: @uid', [
        '@uid' => $payload['uid'],
      ]);
      return null;
    }

    // Generate new tokens
    $new_tokens = $this->generateTokens($user);

    // Optionally revoke old refresh token
    $this->revokeRefreshToken($payload['uid'], $payload['jti']);

    return $new_tokens;
  }

  /**
   * Revokes a refresh token.
   */
  public function revokeRefreshToken(int $uid, string $jti): void
  {
    $key = "siwe_server:refresh_tokens:$uid";
    $tokens = $this->state->get($key, []);

    if (isset($tokens[$jti])) {
      unset($tokens[$jti]);
      $this->state->set($key, $tokens);

      $this->logger->info('Revoked refresh token for user @uid', ['@uid' => $uid]);
    }
  }

  /**
   * Revokes all refresh tokens for a user.
   */
  public function revokeAllUserTokens(int $uid): void
  {
    $key = "siwe_server:refresh_tokens:$uid";
    $this->state->delete($key);

    $this->logger->info('Revoked all refresh tokens for user @uid', ['@uid' => $uid]);
  }

  /**
   * Gets the public key for external validation.
   */
  public function getPublicKey(): string
  {
    return $this->publicKey;
  }

  /**
   * Gets JWT configuration for external consumers.
   */
  public function getJwtConfig(): array
  {
    return [
      'algorithm' => $this->algorithm,
      'issuer' => \Drupal::request()->getSchemeAndHttpHost(),
      'audience' => $this->config->get('jwt_audience') ?: 'drupal-siwe',
      'public_key' => $this->publicKey,
    ];
  }

  /**
   * Generates a unique JWT ID.
   */
  protected function generateJti(): string
  {
    return bin2hex(random_bytes(16));
  }

  /**
   * Gets access token TTL.
   */
  protected function getAccessTokenTtl(): int
  {
    return $this->config->get('access_token_ttl') ?: 900; // 15 minutes default
  }

  /**
   * Gets refresh token TTL.
   */
  protected function getRefreshTokenTtl(): int
  {
    return $this->config->get('refresh_token_ttl') ?: 604800; // 7 days default
  }

  /**
   * Stores refresh token for validation.
   */
  protected function storeRefreshToken(int $uid, string $jti, int $expiration): void
  {
    $key = "siwe_server:refresh_tokens:$uid";
    $tokens = $this->state->get($key, []);

    // Clean expired tokens
    $current_time = time();
    $tokens = array_filter($tokens, fn($exp) => $exp > $current_time);

    // Add new token
    $tokens[$jti] = $expiration;

    $this->state->set($key, $tokens);
  }

  /**
   * Checks if refresh token is valid.
   */
  protected function isRefreshTokenValid(int $uid, string $jti): bool
  {
    $key = "siwe_server:refresh_tokens:$uid";
    $tokens = $this->state->get($key, []);

    return isset($tokens[$jti]) && $tokens[$jti] > time();
  }

  /**
   * Initializes or loads JWT keys.
   */
  protected function initializeKeys(): void
  {
    $private_key = $this->state->get('siwe_server:jwt_private_key');
    $public_key = $this->state->get('siwe_server:jwt_public_key');

    if (!$private_key || !$public_key) {
      $this->generateKeyPair();
    } else {
      $this->privateKey = $private_key;
      $this->publicKey = $public_key;
    }
  }

  /**
   * Generates a new RSA key pair.
   */
  protected function generateKeyPair(): void
  {
    $config = [
      'private_key_bits' => 2048,
      'private_key_type' => OPENSSL_KEYTYPE_RSA,
    ];

    $res = openssl_pkey_new($config);

    if (!$res) {
      throw new \RuntimeException('Failed to generate RSA key pair');
    }

    // Export private key
    if (!openssl_pkey_export($res, $private_key)) {
      throw new \RuntimeException('Failed to export private key');
    }

    // Get public key
    $public_key_details = openssl_pkey_get_details($res);
    if (!$public_key_details || !isset($public_key_details['key'])) {
      throw new \RuntimeException('Failed to extract public key');
    }

    $public_key = $public_key_details['key'];

    // Store keys securely in state
    $this->state->setMultiple([
      'siwe_server:jwt_private_key' => $private_key,
      'siwe_server:jwt_public_key' => $public_key,
    ]);

    $this->privateKey = $private_key;
    $this->publicKey = $public_key;

    $this->logger->info('Generated new JWT key pair');
  }
}