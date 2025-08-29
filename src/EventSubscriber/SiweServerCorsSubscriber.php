<?php

namespace Drupal\siwe_server\EventSubscriber;

use Drupal\Core\Config\ConfigFactoryInterface;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * Event subscriber for adding CORS headers to SIWE server responses.
 */
class SiweServerCorsSubscriber implements EventSubscriberInterface {

  protected $config;

  public function __construct(ConfigFactoryInterface $config_factory) {
    $this->config = $config_factory->get('siwe_server.settings');
  }

  /**
   * {@inheritdoc}
   */
  public static function getSubscribedEvents() {
    return [
      KernelEvents::RESPONSE => ['onResponse'],
    ];
  }

  /**
   * Adds CORS headers to responses.
   */
  public function onResponse(ResponseEvent $event) {
    $response = $event->getResponse();
    $request = $event->getRequest();

    $allowed_origins = $this->config->get('allowed_origins') ?? [];
    $origin = $request->headers->get('Origin');

    if (in_array($origin, $allowed_origins)) {
      $response->headers->set('Access-Control-Allow-Origin', $origin);
      $response->headers->set('Access-Control-Allow-Credentials', 'true');
      $response->headers->set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
      $response->headers->set('Access-Control-Allow-Headers', 'Content-Type, Authorization, Accept');
      $response->headers->set('Access-Control-Max-Age', '86400');
    }
    
    // Handle preflight requests
    if ($request->getMethod() === 'OPTIONS') {
      $response->setStatusCode(204);
      $response->headers->set('Access-Control-Allow-Origin', $origin);
      $response->headers->set('Access-Control-Allow-Credentials', 'true');
      $response->headers->set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
      $response->headers->set('Access-Control-Allow-Headers', 'Content-Type, Authorization, Accept');
      $response->headers->set('Access-Control-Max-Age', '86400');
    }
  }
}