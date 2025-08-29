# SIWE Server for Drupal

## Overview

This module provides API endpoints for SIWE authentication with Next-Drupal, including JWT token generation and validation.

## Requirements

- Drupal 10.0 or higher
- PHP 8.1 or higher
- Composer
- siwe_login module
- firebase/php-jwt library

## Installation

1. Install via Composer: `composer require drupal/siwe_server`
2. Enable modules: `drush en siwe_server -y`
3. Import configuration: `drush config-import --partial --source=modules/custom/siwe_server/config/install`
4. Configure at `/admin/config/services/siwe-server`

## API Endpoints

- `GET /api/siwe/nonce` - Get authentication nonce
- `POST /api/siwe/auth` - Authenticate with SIWE
- `POST /api/siwe/refresh` - Refresh access token
- `POST /api/siwe/logout` - Logout user

## Configuration

See `/admin/config/services/siwe-server` for configuration options.

## Security

- Uses JWT tokens with RS256 algorithm
- Configurable token expiration
- CORS support

## Support

Report issues at: https://github.com/your-org/siwe_drupal/issues

## Implementation Details

This module provides REST API endpoints for SIWE authentication that are compatible with Next-Drupal:

1. The `/api/siwe/auth` endpoint validates the SIWE message and signature using the siwe_login module
2. If the authentication is successful, JWT tokens (access and refresh) are generated
3. The JWT tokens can be used to authenticate subsequent requests to Drupal
4. The `/api/siwe/refresh` endpoint allows refreshing the access token using the refresh token
5. The `/api/siwe/logout` endpoint invalidates the refresh token

## JWT Token Generation

The module automatically generates RSA keys for JWT token signing and stores them in the Drupal state system. The public key can be retrieved using the `getPublicKey()` method of the JwtService class.

## CORS Configuration

The module includes CORS support with the following default configuration:
- Allowed origins: `http://localhost:3000`, `https://your-nextjs-app.com`
- Allowed methods: `GET`, `POST`, `OPTIONS`
- Allowed headers: `Content-Type`, `Authorization`, `Accept`
- Credentials: allowed
- Max age: 86400 seconds (24 hours)

This configuration can be modified in the module settings.