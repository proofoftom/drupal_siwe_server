<?php

namespace Drupal\siwe_server\Plugin\rest\resource;

use Drupal\rest\Plugin\ResourceBase;
use Drupal\rest\ResourceResponse;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\Request;
use Drupal\siwe_login\Service\SiweAuthService;
use Drupal\siwe_server\Service\NextDrupalAuthService;
use Psr\Log\LoggerInterface;

/**
 * Provides a REST resource for SIWE authentication.
 *
 * @RestResource(
 *   id = "siwe_auth_resource",
 *   label = @Translation("SIWE Authentication Resource"),
 *   uri_paths = {
 *     "create" = "/api/siwe/auth",
 *     "canonical" = "/api/siwe/auth/{id}"
 *   }
 * )
 */
class SiweAuthResource extends ResourceBase {

  protected $siweAuthService;
  protected $nextDrupalAuthService;
  protected $currentRequest;

  public function __construct(
    array $configuration,
    $plugin_id,
    $plugin_definition,
    array $serializer_formats,
    LoggerInterface $logger,
    SiweAuthService $siwe_auth_service,
    NextDrupalAuthService $next_drupal_auth_service,
    Request $current_request,
  ) {
    parent::__construct($configuration, $plugin_id, $plugin_definition, $serializer_formats, $logger);
    $this->siweAuthService = $siwe_auth_service;
    $this->nextDrupalAuthService = $next_drupal_auth_service;
    $this->currentRequest = $current_request;
  }

  /**
   *
   */
  public static function create(ContainerInterface $container, array $configuration, $plugin_id, $plugin_definition) {
    return new static(
      $configuration,
      $plugin_id,
      $plugin_definition,
      $container->getParameter('serializer.formats'),
      $container->get('logger.factory')->get('siwe_server'),
      $container->get('siwe_login.auth_service'),
      $container->get('siwe_server.next_drupal_auth'),
      $container->get('request_stack')->getCurrentRequest()
    );
  }

  /**
   * Responds to POST requests for SIWE authentication.
   */
  public function post(array $data): ResourceResponse {
    try {
      // Validate required fields.
      $this->validateRequestData($data);

      // Authenticate using SIWE.
      $user = $this->siweAuthService->authenticate($data);

      if (!$user) {
        return new ResourceResponse([
          'error' => 'Authentication failed',
        ], 401);
      }

      // Programmatically log in the user.
      \Drupal::service('session_manager')->start();
      \Drupal::service('current_user')->setAccount($user);

      // Generate JWT token using the JWT module.
      $jwt_auth = \Drupal::service('jwt.authentication.jwt');
      $access_token = $jwt_auth->generateToken();

      // Prepare response compatible with Next-Drupal.
      $tokens = [
        'access_token' => $access_token,
        'token_type' => 'Bearer',
      ];

      $response_data = $this->nextDrupalAuthService->formatAuthResponse($user, $tokens);

      $response = new ResourceResponse($response_data, 200);

      // Set appropriate headers.
      $response->addCacheableDependency(['#cache' => ['max-age' => 0]]);

      return $response;
    }
    catch (\Exception $e) {
      $this->logger->error('SIWE authentication failed: @message', [
        '@message' => $e->getMessage(),
      ]);

      return new ResourceResponse([
        'error' => $e->getMessage(),
      ], 400);
    }
  }

  /**
   * Validates request data.
   */
  protected function validateRequestData(array $data): void {
    $required = ['message', 'signature', 'address'];

    foreach ($required as $field) {
      if (empty($data[$field])) {
        throw new \InvalidArgumentException("Missing required field: $field");
      }
    }
  }

}
