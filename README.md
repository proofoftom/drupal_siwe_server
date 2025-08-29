# SIWE Server for Drupal

## Overview

This module provides API endpoints for SIWE authentication with Next-Drupal, using the Drupal JWT module for token generation and validation.

## Requirements

- Drupal 10.0 or higher
- PHP 8.1 or higher
- Composer
- siwe_login module
- Drupal JWT module

## Installation

1. Install via Composer: `composer require drupal/siwe_server`
2. Enable modules: `drush en siwe_server jwt jwt_auth_issuer -y`
3. Configure the JWT module at `/admin/config/system/jwt` (see below)
4. Import configuration: `drush config-import --partial --source=modules/custom/siwe_server/config/install`
5. Configure at `/admin/config/services/siwe-server`

## JWT Module Configuration

This module now relies on the Drupal JWT module for token generation. You'll need to:

1. Create a key at `/admin/config/system/keys`:
   - Type: JWT HMAC Key or JWT RSA Key
   - Provider: Configuration or File
2. Configure the JWT module at `/admin/config/system/jwt` to use your key

## API Endpoints

- `GET /api/siwe/nonce` - Get authentication nonce
- `POST /api/siwe/auth` - Authenticate with SIWE
- `POST /api/siwe/refresh` - Refresh access token (not currently supported with JWT module)
- `POST /api/siwe/logout` - Logout user

## Configuration

See `/admin/config/services/siwe-server` for configuration options.

## Security

- Uses JWT tokens with configurable algorithm (defaults to HS256)
- Configurable token expiration
- CORS support

## Support

Report issues at: [https://github.com/proofoftom/drupal_siwe_server/issues](https://github.com/proofoftom/drupal_siwe_server/issues)

## Implementation Details

This module provides REST API endpoints for SIWE authentication that are compatible with Next-Drupal:

1. The `/api/siwe/auth` endpoint validates the SIWE message and signature using the siwe_login module
2. If the authentication is successful, a JWT token is generated using the Drupal JWT module
3. The JWT token can be used to authenticate subsequent requests to Drupal
4. The `/api/siwe/logout` endpoint handles user logout

## CORS Configuration

The module includes CORS support with the following default configuration:

- Allowed origins: `http://localhost:3000`, `https://your-nextjs-app.com`
- Allowed methods: `GET`, `POST`, `OPTIONS`
- Allowed headers: `Content-Type`, `Authorization`, `Accept`
- Credentials: allowed
- Max age: 86400 seconds (24 hours)

This configuration can be modified in the module settings.
