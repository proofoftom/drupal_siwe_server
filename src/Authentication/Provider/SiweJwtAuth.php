<?php

namespace Drupal\siwe_server\Authentication\Provider;

use Drupal\Core\Authentication\AuthenticationProviderInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Session\AccountInterface;
use Drupal\siwe_server\Service\JwtService;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\RequestEvent;

/**
 * Authentication provider for SIWE JWT tokens.
 */
class SiweJwtAuth implements AuthenticationProviderInterface {

  protected $jwtService;
  protected $entityTypeManager;

  public function __construct(JwtService $jwt_service, EntityTypeManagerInterface $entity_type_manager) {
    $this->jwtService = $jwt_service;
    $this->entityTypeManager = $entity_type_manager;
  }

  /**
   * {@inheritdoc}
   */
  public function applies(Request $request) {
    // Check if the request has an Authorization header with a Bearer token
    return strpos($request->headers->get('Authorization', ''), 'Bearer ') === 0;
  }

  /**
   * {@inheritdoc}
   */
  public function authenticate(Request $request) {
    $auth_header = $request->headers->get('Authorization');
    $token = substr($auth_header, 7); // Remove 'Bearer ' prefix

    $payload = $this->jwtService->validateToken($token);

    if (!$payload || $payload['type'] !== 'access') {
      return NULL;
    }

    // Load the user
    $user = $this->entityTypeManager
      ->getStorage('user')
      ->load($payload['uid']);

    if (!$user) {
      return NULL;
    }

    return $user;
  }
}