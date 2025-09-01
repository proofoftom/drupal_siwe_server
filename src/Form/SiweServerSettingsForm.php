<?php

namespace Drupal\siwe_server\Form;

use Drupal\Core\Form\ConfigFormBase;
use Drupal\Core\Form\FormStateInterface;

/**
 * Form for SIWE server settings.
 */
class SiweServerSettingsForm extends ConfigFormBase
{

  /**
   * {@inheritdoc}
   */
  public function getFormId()
  {
    return 'siwe_server_settings';
  }

  /**
   * {@inheritdoc}
   */
  protected function getEditableConfigNames()
  {
    return [
      'siwe_server.settings',
    ];
  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state)
  {
    $config = $this->config('siwe_server.settings');

    $form['allow_drupal_login'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Allow Drupal login via SIWE Login Block'),
      '#default_value' => $config->get('allow_drupal_login') !== FALSE,
      '#description' => $this->t('Allow users to login to the Drupal site using the SIWE Login Block. When enabled, the current site domain (@domain) will be included in the allowed domains for SIWE validation.', ['@domain' => \Drupal::request()->getHost()]),
    ];

    $form['allowed_domains'] = [
      '#type' => 'textarea',
      '#title' => $this->t('Allowed Frontends'),
      '#default_value' => implode("\n", $config->get('allowed_domains') ?: []),
      '#description' => $this->t('A list of allowed domains for SIWE messages, one per line. These will be used for SIWE domain validation. Protocols (http://, https://) and paths will be ignored.'),
    ];

    return parent::buildForm($form, $form_state);
  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state)
  {
    // Process the allowed origins into an array.
    $allowed_domains = array_filter(
      array_map('trim', explode("\n", $form_state->getValue('allowed_domains')))
    );

    $this->config('siwe_server.settings')
      ->set('allow_drupal_login', $form_state->getValue('allow_drupal_login'))
      ->set('allowed_domains', $allowed_domains)
      ->save();

    // Automatically extract domains for SIWE Login configuration
    if (!empty($allowed_domains) || $form_state->getValue('allow_drupal_login')) {
      // Extract domains from origins
      $siwe_domains = [];

      // Add current host if Drupal login is allowed
      if ($form_state->getValue('allow_drupal_login')) {
        $siwe_domains[] = \Drupal::request()->getHost();
      }

      // Extract domains from allowed origins (remove protocol and path)
      foreach ($allowed_domains as $origin) {
        // Remove protocol (http://, https://) and path if present
        $domain = preg_replace('#^https?://#', '', $origin);
        $domain = explode('/', $domain)[0];
        $siwe_domains[] = $domain;
      }

      // Remove duplicates
      $siwe_domains = array_unique($siwe_domains);

      // Update SIWE Login configuration with all domains (comma-separated)
      // This allows SIWE Login to validate against multiple domains
      $siwe_login_config = \Drupal::configFactory()->getEditable('siwe_login.settings');
      $siwe_login_config->set('expected_domain', implode(',', $siwe_domains))->save();
    }

    parent::submitForm($form, $form_state);
  }
}