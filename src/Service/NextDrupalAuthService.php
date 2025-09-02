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
    // The JWT module only provides an access_token, not refresh tokens.
    $response = [
      'access_token' => $tokens['access_token'],
      'token_type' => 'Bearer',
      'user' => [
        'uid' => $user->id(),
        'uuid' => $user->uuid(),
        'name' => $user->getAccountName(),
        'mail' => $user->getEmail(),
        'ethereum_address' => $user->get('field_ethereum_address')->value ?? NULL,
        'roles' => array_values($user->getRoles()),
        'display_name' => $user->getDisplayName(),
        'url' => Url::fromRoute('entity.user.canonical', ['user' => $user->id()], ['absolute' => TRUE])->toString(),
      ],
    ];

    // Add expires_in if it exists in the tokens array.
    if (isset($tokens['expires_in'])) {
      $response['expires_in'] = $tokens['expires_in'];
    }

    return $response;
  }

  /**
   * Validates Next-Drupal authentication request.
   */
  public function validateNextDrupalRequest(array $headers): bool {
    // Validate expected headers from Next-Drupal.
    if (!isset($headers['Authorization'])) {
      return FALSE;
    }

    // Additional validation for Next-Drupal specific requirements.
    return TRUE;
  }

}
