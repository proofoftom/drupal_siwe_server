<?php

namespace Drupal\siwe_server\Service;

use Drupal\user\UserInterface;
use Drupal\Core\Url;

/**
 * Service for Next-Drupal authentication compatibility.
 */
class NextDrupalAuthService {

  /**
   * Formats authentication response for Next-Drupal.
   */
  public function formatAuthResponse(UserInterface $user, array $tokens): array {
    return [
      'access_token' => $tokens['access_token'],
      'refresh_token' => $tokens['refresh_token'],
      'expires_in' => $tokens['expires_in'],
      'token_type' => 'Bearer',
      'user' => [
        'uid' => $user->id(),
        'uuid' => $user->uuid(),
        'name' => $user->getAccountName(),
        'mail' => $user->getEmail(),
        'ethereum_address' => $user->get('field_ethereum_address')->value,
        'roles' => array_values($user->getRoles()),
        'display_name' => $user->getDisplayName(),
        'url' => Url::fromRoute('entity.user.canonical', ['user' => $user->id()], ['absolute' => TRUE])->toString(),
      ],
    ];
  }

  /**
   * Validates Next-Drupal authentication request.
   */
  public function validateNextDrupalRequest(array $headers): bool {
    // Validate expected headers from Next-Drupal
    if (!isset($headers['Authorization'])) {
      return FALSE;
    }

    // Additional validation for Next-Drupal specific requirements
    return TRUE;
  }
}