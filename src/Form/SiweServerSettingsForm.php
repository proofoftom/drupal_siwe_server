<?php

namespace Drupal\siwe_server\Form;

use Drupal\Core\Form\ConfigFormBase;
use Drupal\Core\Form\FormStateInterface;

/**
 * Form for SIWE server settings.
 */
class SiweServerSettingsForm extends ConfigFormBase {

  /**
   * {@inheritdoc}
   */
  public function getFormId() {
    return 'siwe_server_settings';
  }

  /**
   * {@inheritdoc}
   */
  protected function getEditableConfigNames() {
    return [
      'siwe_server.settings',
    ];
  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state) {
    $config = $this->config('siwe_server.settings');

    $form['jwt_audience'] = [
      '#type' => 'textfield',
      '#title' => $this->t('JWT Audience'),
      '#default_value' => $config->get('jwt_audience'),
      '#description' => $this->t('The audience for JWT tokens.'),
    ];

    $form['cors_enabled'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Enable CORS'),
      '#default_value' => $config->get('cors_enabled'),
      '#description' => $this->t('Enable CORS for API endpoints.'),
    ];

    $form['allowed_origins'] = [
      '#type' => 'textarea',
      '#title' => $this->t('Allowed Origins'),
      '#default_value' => implode("\n", $config->get('allowed_origins') ?: []),
      '#description' => $this->t('A list of allowed origins for CORS, one per line.'),
      '#states' => [
        'visible' => [
          ':input[name="cors_enabled"]' => ['checked' => TRUE],
        ],
      ],
    ];

    return parent::buildForm($form, $form_state);
  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state) {
    // Process the allowed origins into an array.
    $allowed_origins = array_filter(
      array_map('trim', explode("\n", $form_state->getValue('allowed_origins')))
    );

    $this->config('siwe_server.settings')
      ->set('jwt_audience', $form_state->getValue('jwt_audience'))
      ->set('cors_enabled', $form_state->getValue('cors_enabled'))
      ->set('allowed_origins', $allowed_origins)
      ->save();

    parent::submitForm($form, $form_state);
  }
}