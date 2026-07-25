<?php
/*
Plugin Name: Microsoft 365 Login
Description: Sign in to the YOURLS admin area with a Microsoft 365 / Entra ID (Azure AD) account, using OpenID Connect (Authorization Code + PKCE). Local username/password logins keep working as a fallback. Configure under Plugins &rarr; Microsoft 365 Login.
Version: 1.0
Author: Michal Lenhart
Author URI: https://skolskyit.guru
*/

// No direct call
if( !defined( 'YOURLS_ABSPATH' ) ) die();

if( !defined( 'YOURLS_M365_SESSION_COOKIE' ) ) define( 'YOURLS_M365_SESSION_COOKIE', 'yourls_m365_session' );
if( !defined( 'YOURLS_M365_STATE_COOKIE' ) )   define( 'YOURLS_M365_STATE_COOKIE', 'yourls_m365_state' );

/**
 * Map of setting keys to optional PHP constants that, if defined in config.php, take precedence
 * over the value saved from the admin settings page. Useful to keep secrets out of the database
 * (eg define them via config.php or environment-driven config on the server instead).
 */
function yourls_m365_const_map() {
    return array(
        'tenant_id'       => 'YOURLS_M365_TENANT_ID',
        'client_id'       => 'YOURLS_M365_CLIENT_ID',
        'client_secret'   => 'YOURLS_M365_CLIENT_SECRET',
        'allowed_groups'  => 'YOURLS_M365_ALLOWED_GROUPS',
    );
}

function yourls_m365_setting_is_locked( $key ) {
    $map = yourls_m365_const_map();
    return isset( $map[ $key ] ) && defined( $map[ $key ] );
}

function yourls_m365_get_setting( $key, $default = '' ) {
    $map = yourls_m365_const_map();
    if( isset( $map[ $key ] ) && defined( $map[ $key ] ) ) {
        return constant( $map[ $key ] );
    }
    return yourls_get_option( 'm365_' . $key, $default );
}

function yourls_m365_list_setting( $key ) {
    $raw = (string) yourls_m365_get_setting( $key, '' );
    $items = preg_split( '/[\s,]+/', strtolower( trim( $raw ) ), -1, PREG_SPLIT_NO_EMPTY );
    return $items ?: array();
}

/**
 * Check whether a signed-in Microsoft 365 account is allowed to log in, based solely on
 * Entra ID group membership. Fails closed: if no group is configured, or the account's group
 * membership couldn't be evaluated (see the settings page for details), nobody is allowed in.
 *
 * @param string $email   The account's email / preferred_username, lower-cased. Only used for
 *                         identification (becomes the YOURLS username) and for filters/logging.
 * @param array  $groups  Entra ID group Object IDs (GUIDs) the account belongs to, from the
 *                         ID token's "groups" claim (empty if group claims aren't enabled, or
 *                         if the account is in too many groups for Microsoft to list them all
 *                         in the token -- see the settings page for details).
 */
function yourls_m365_is_allowed( $email, $groups = array() ) {
    $email = strtolower( trim( (string) $email ) );
    if( $email === '' ) {
        return false;
    }

    $allowed_groups = yourls_m365_list_setting( 'allowed_groups' );
    if( !empty( $allowed_groups ) && is_array( $groups ) ) {
        foreach( $groups as $group_id ) {
            if( in_array( strtolower( trim( (string) $group_id ) ), $allowed_groups, true ) ) {
                return true;
            }
        }
    }

    return yourls_apply_filter( 'm365_is_allowed', false, $email, $groups );
}

/*
 * Microsoft identity platform endpoints
 */

function yourls_m365_authority() {
    $tenant = rawurlencode( (string) yourls_m365_get_setting( 'tenant_id' ) );
    return 'https://login.microsoftonline.com/' . $tenant;
}
function yourls_m365_authorize_endpoint() { return yourls_m365_authority() . '/oauth2/v2.0/authorize'; }
function yourls_m365_token_endpoint()     { return yourls_m365_authority() . '/oauth2/v2.0/token'; }
function yourls_m365_jwks_endpoint()      { return yourls_m365_authority() . '/discovery/v2.0/keys'; }
function yourls_m365_issuer()             { return yourls_m365_authority() . '/v2.0'; }
function yourls_m365_redirect_uri()       { return yourls_admin_url( 'index.php' ); }

/*
 * Base64url and signed-cookie helpers (used for the transient "state/PKCE" cookie and the
 * post-login session cookie -- both are HMAC-signed with a key derived from YOURLS_COOKIEKEY,
 * so nothing new needs to be configured, and neither can be forged without that key).
 */

function yourls_m365_b64url_encode( $data ) {
    return rtrim( strtr( base64_encode( $data ), '+/', '-_' ), '=' );
}

function yourls_m365_b64url_decode( $data ) {
    $pad = strlen( $data ) % 4;
    if( $pad ) {
        $data .= str_repeat( '=', 4 - $pad );
    }
    return base64_decode( strtr( $data, '-_', '+/' ) );
}

function yourls_m365_cookie_secret() {
    $base = defined( 'YOURLS_COOKIEKEY' ) ? YOURLS_COOKIEKEY : md5( __FILE__ );
    return hash_hmac( 'sha256', 'yourls-microsoft365-login', $base );
}

function yourls_m365_cookie_domain() {
    $domain = parse_url( yourls_get_yourls_site(), PHP_URL_HOST );
    return ( $domain === 'localhost' ) ? '' : $domain;
}

function yourls_m365_set_signed_cookie( $name, array $payload, $ttl ) {
    $encoded   = yourls_m365_b64url_encode( json_encode( $payload ) );
    $signature = hash_hmac( 'sha256', $encoded, yourls_m365_cookie_secret() );
    yourls_setcookie( $name, $encoded . '.' . $signature, time() + $ttl, '/', yourls_m365_cookie_domain(), yourls_is_ssl(), true );
}

function yourls_m365_read_signed_cookie( $value ) {
    if( !is_string( $value ) || strpos( $value, '.' ) === false ) {
        return false;
    }
    list( $encoded, $signature ) = explode( '.', $value, 2 );
    if( !hash_equals( hash_hmac( 'sha256', $encoded, yourls_m365_cookie_secret() ), $signature ) ) {
        return false;
    }
    $payload = json_decode( yourls_m365_b64url_decode( $encoded ), true );
    return is_array( $payload ) ? $payload : false;
}

function yourls_m365_clear_cookie( $name ) {
    yourls_setcookie( $name, '', time() - 3600, '/', yourls_m365_cookie_domain(), yourls_is_ssl(), true );
}

/*
 * OpenID Connect: JWKS fetch (cached) and ID token validation
 */

function yourls_m365_get_jwks() {
    $cache = yourls_get_option( 'm365_jwks_cache' );
    $fresh = is_array( $cache ) && !empty( $cache['keys'] ) && ( time() - (int)($cache['fetched'] ?? 0) ) < 43200;
    if( $fresh ) {
        return $cache['keys'];
    }

    $body = yourls_http_get_body( yourls_m365_jwks_endpoint() );
    $data = $body ? json_decode( $body, true ) : null;

    if( empty( $data['keys'] ) ) {
        // Fetch failed: fall back to a stale cache rather than hard-failing every login
        return is_array( $cache ) ? ( $cache['keys'] ?? array() ) : array();
    }

    yourls_update_option( 'm365_jwks_cache', array( 'fetched' => time(), 'keys' => $data['keys'] ) );
    return $data['keys'];
}

function yourls_m365_find_public_key( $kid ) {
    foreach( yourls_m365_get_jwks() as $key ) {
        if( ( $key['kid'] ?? '' ) === $kid && !empty( $key['x5c'][0] ) ) {
            $pem = "-----BEGIN CERTIFICATE-----\n" . chunk_split( $key['x5c'][0], 64, "\n" ) . "-----END CERTIFICATE-----\n";
            $resource = openssl_pkey_get_public( $pem );
            if( $resource !== false ) {
                return $resource;
            }
        }
    }
    return false;
}

/**
 * Verify an ID token's signature (RS256, against Microsoft's published JWKS) and its
 * standard claims (issuer, audience, expiry, not-before). Returns the decoded claims on
 * success, false otherwise.
 */
function yourls_m365_verify_id_token( $id_token, $client_id, $issuer ) {
    $parts = explode( '.', (string) $id_token );
    if( count( $parts ) !== 3 ) {
        return false;
    }
    list( $h64, $p64, $s64 ) = $parts;

    $header    = json_decode( yourls_m365_b64url_decode( $h64 ), true );
    $payload   = json_decode( yourls_m365_b64url_decode( $p64 ), true );
    $signature = yourls_m365_b64url_decode( $s64 );

    if( !is_array( $header ) || !is_array( $payload ) ) {
        return false;
    }
    if( ( $header['alg'] ?? '' ) !== 'RS256' || empty( $header['kid'] ) ) {
        return false;
    }

    $public_key = yourls_m365_find_public_key( $header['kid'] );
    if( !$public_key ) {
        return false;
    }

    if( openssl_verify( $h64 . '.' . $p64, $signature, $public_key, OPENSSL_ALGO_SHA256 ) !== 1 ) {
        return false;
    }

    if( ( $payload['iss'] ?? '' ) !== $issuer ) {
        return false;
    }
    if( ( $payload['aud'] ?? '' ) !== $client_id ) {
        return false;
    }

    $now = time();
    if( empty( $payload['exp'] ) || $now > ( (int) $payload['exp'] + 60 ) ) {
        return false;
    }
    if( !empty( $payload['nbf'] ) && $now < ( (int) $payload['nbf'] - 60 ) ) {
        return false;
    }

    return $payload;
}

/*
 * The actual login flow, hooked into YOURLS' auth "shunt" filter so it runs before -- and can
 * fully bypass -- the local username/password check. If none of our conditions match, $pre is
 * returned unchanged so the normal (local account) login continues to work.
 */

yourls_add_filter( 'shunt_is_valid_user', 'yourls_m365_shunt_is_valid_user' );

function yourls_m365_shunt_is_valid_user( $pre ) {
    // Don't touch API auth (signature/timestamp) -- this plugin is for the browser admin UI only
    if( yourls_is_API() ) {
        return $pre;
    }

    // Let core handle the logout request itself; we clean up our own cookie via the 'logout' action
    if( isset( $_GET['action'] ) && $_GET['action'] === 'logout' ) {
        return $pre;
    }

    // Step 2: back from Microsoft with an authorization code
    if( isset( $_GET['code'] ) && is_string( $_GET['code'] ) && isset( $_GET['state'] ) && is_string( $_GET['state'] ) ) {
        return yourls_m365_handle_callback();
    }

    // Step 1: user clicked "Sign in with Microsoft 365"
    if( isset( $_GET['yourls_m365_login'] ) ) {
        yourls_m365_start_login();
        // yourls_m365_start_login() redirects and dies when properly configured;
        // if it returns, configuration is missing, so fall through to normal login.
    }

    // Step 3+: an existing, still-valid Microsoft 365 session cookie
    if( isset( $_COOKIE[ YOURLS_M365_SESSION_COOKIE ] ) ) {
        $session = yourls_m365_read_signed_cookie( $_COOKIE[ YOURLS_M365_SESSION_COOKIE ] );
        $email   = is_array( $session ) ? ( $session['email'] ?? '' ) : '';
        $groups  = ( is_array( $session ) && is_array( $session['groups'] ?? null ) ) ? $session['groups'] : array();
        $valid   = $session && !empty( $session['exp'] ) && $session['exp'] > time() && yourls_m365_is_allowed( $email, $groups );

        if( $valid ) {
            yourls_set_user( $email );
            return true;
        }

        // Expired, tampered, or no longer allowed: stop sending a stale cookie
        yourls_m365_clear_cookie( YOURLS_M365_SESSION_COOKIE );
    }

    return $pre;
}

function yourls_m365_start_login() {
    $client_id = yourls_m365_get_setting( 'client_id' );
    $tenant_id = yourls_m365_get_setting( 'tenant_id' );
    if( !$client_id || !$tenant_id ) {
        return; // not configured: fall through to the regular login form
    }

    $verifier  = bin2hex( random_bytes( 32 ) );
    $challenge = yourls_m365_b64url_encode( hash( 'sha256', $verifier, true ) );
    $state     = bin2hex( random_bytes( 16 ) );

    yourls_m365_set_signed_cookie( YOURLS_M365_STATE_COOKIE, array(
        's'   => $state,
        'v'   => $verifier,
        'exp' => time() + 600,
    ), 600 );

    $params = array(
        'client_id'             => $client_id,
        'response_type'         => 'code',
        'redirect_uri'          => yourls_m365_redirect_uri(),
        'response_mode'         => 'query',
        'scope'                 => 'openid profile email',
        'state'                 => $state,
        'code_challenge'        => $challenge,
        'code_challenge_method' => 'S256',
        'prompt'                => 'select_account',
    );

    yourls_redirect( yourls_m365_authorize_endpoint() . '?' . http_build_query( $params ), 302 );
    die();
}

function yourls_m365_handle_callback() {
    $client_id     = yourls_m365_get_setting( 'client_id' );
    $client_secret = yourls_m365_get_setting( 'client_secret' );
    $tenant_id     = yourls_m365_get_setting( 'tenant_id' );

    if( !$client_id || !$client_secret || !$tenant_id ) {
        return yourls__( 'Microsoft 365 login is not configured.' );
    }

    if( !isset( $_COOKIE[ YOURLS_M365_STATE_COOKIE ] ) ) {
        return yourls__( 'Microsoft 365 login failed: your login attempt expired. Please try again.' );
    }

    $stored = yourls_m365_read_signed_cookie( $_COOKIE[ YOURLS_M365_STATE_COOKIE ] );
    yourls_m365_clear_cookie( YOURLS_M365_STATE_COOKIE );

    if( !$stored || empty( $stored['exp'] ) || $stored['exp'] < time() ) {
        return yourls__( 'Microsoft 365 login failed: your login attempt expired. Please try again.' );
    }

    if( !hash_equals( (string) $stored['s'], (string) $_GET['state'] ) ) {
        return yourls__( 'Microsoft 365 login failed: state mismatch. Please try again.' );
    }

    $response = yourls_http_post( yourls_m365_token_endpoint(), array(), array(
        'client_id'     => $client_id,
        'client_secret' => $client_secret,
        'grant_type'    => 'authorization_code',
        'code'          => (string) $_GET['code'],
        'redirect_uri'  => yourls_m365_redirect_uri(),
        'code_verifier' => $stored['v'],
        'scope'         => 'openid profile email',
    ) );

    if( is_string( $response ) || empty( $response->status_code ) || $response->status_code !== 200 ) {
        yourls_debug_log( 'Microsoft 365 login: token endpoint error - ' . ( is_string( $response ) ? $response : ( $response->body ?? 'unknown error' ) ) );
        return yourls__( 'Microsoft 365 login failed: could not reach Microsoft to complete sign-in.' );
    }

    $token_data = json_decode( $response->body, true );
    if( empty( $token_data['id_token'] ) ) {
        return yourls__( 'Microsoft 365 login failed: no identity token received.' );
    }

    $claims = yourls_m365_verify_id_token( $token_data['id_token'], $client_id, yourls_m365_issuer() );
    if( !$claims ) {
        return yourls__( 'Microsoft 365 login failed: identity token could not be verified.' );
    }

    $email = strtolower( (string) ( $claims['preferred_username'] ?? $claims['email'] ?? '' ) );
    if( !$email ) {
        return yourls__( 'Microsoft 365 login failed: no email address in identity token.' );
    }

    $groups = array();
    if( is_array( $claims['groups'] ?? null ) ) {
        $groups = $claims['groups'];
    } elseif( isset( $claims['_claim_names']['groups'] ) ) {
        // "Overage" -- the account belongs to too many groups for Microsoft to list them all in
        // the token, so group membership can't be evaluated for this sign-in. See the settings
        // page for details.
        yourls_debug_log( "Microsoft 365 login: group-membership overage for $email, group allow-list could not be evaluated" );
    }

    if( !yourls_m365_is_allowed( $email, $groups ) ) {
        yourls_debug_log( "Microsoft 365 login: rejected account not on allow-list: $email" );
        return yourls__( 'Microsoft 365 login failed: this account is not authorized for this site.' );
    }

    yourls_m365_set_signed_cookie( YOURLS_M365_SESSION_COOKIE, array(
        'email'  => $email,
        'groups' => $groups,
        'exp'    => time() + yourls_get_cookie_life(),
    ), yourls_get_cookie_life() );

    yourls_set_user( $email );
    yourls_do_action( 'login' );

    yourls_redirect( yourls_admin_url( 'index.php' ), 302 );
    die();
}

yourls_add_action( 'logout', 'yourls_m365_on_logout' );
function yourls_m365_on_logout() {
    yourls_m365_clear_cookie( YOURLS_M365_SESSION_COOKIE );
}

/*
 * Login screen: add a "Sign in with Microsoft 365" button above the username/password form,
 * only shown once tenant + client id are configured.
 */

yourls_add_action( 'login_form_top', 'yourls_m365_login_button' );
function yourls_m365_login_button() {
    if( !yourls_m365_get_setting( 'client_id' ) || !yourls_m365_get_setting( 'tenant_id' ) ) {
        return;
    }

    $label = (string) yourls_m365_get_setting( 'button_label' );
    if( $label === '' ) {
        $label = yourls__( 'Sign in with Microsoft 365' );
    }
    $url = yourls_add_query_arg( 'yourls_m365_login', '1', yourls_admin_url( 'index.php' ) );
    ?>
    <p style="text-align:center; margin-bottom:1.5em;">
        <a href="<?php echo yourls_esc_url( $url ); ?>" class="button" style="display:inline-block; text-decoration:none;"><?php echo yourls_esc_html( $label ); ?></a>
    </p>
    <p style="text-align:center; color:#888;"><?php yourls_e( '&mdash; or sign in with a local account &mdash;' ); ?></p>
    <?php
}

/*
 * Admin settings page: Plugins -> Microsoft 365 Login
 */

yourls_add_action( 'plugins_loaded', 'yourls_m365_plugins_loaded' );
function yourls_m365_plugins_loaded() {
    yourls_register_plugin_page( 'm365-login', yourls__( 'Microsoft 365 Login' ), 'yourls_m365_settings_page' );
}

// Note: no need to also hook 'admin_menu' -- YOURLS core already lists registered plugin
// pages (see yourls_register_plugin_page() above) as a submenu under "Manage Plugins".

function yourls_m365_post_string( $key ) {
    return ( isset( $_POST[ $key ] ) && is_string( $_POST[ $key ] ) ) ? trim( $_POST[ $key ] ) : '';
}

// Runs before the page header/notices are drawn, so a save-confirmation notice can be queued in time
yourls_add_action( 'load-m365-login', 'yourls_m365_maybe_save_settings' );
function yourls_m365_maybe_save_settings() {
    if( !isset( $_POST['yourls_m365_nonce'] ) ) {
        return;
    }
    yourls_verify_nonce( 'm365_settings', yourls_m365_post_string( 'yourls_m365_nonce' ) );

    if( !yourls_m365_setting_is_locked( 'tenant_id' ) ) {
        yourls_update_option( 'm365_tenant_id', yourls_m365_post_string( 'tenant_id' ) );
    }
    if( !yourls_m365_setting_is_locked( 'client_id' ) ) {
        yourls_update_option( 'm365_client_id', yourls_m365_post_string( 'client_id' ) );
    }
    if( !yourls_m365_setting_is_locked( 'client_secret' ) && yourls_m365_post_string( 'client_secret' ) !== '' ) {
        // Blank field on save = keep the existing secret unchanged
        yourls_update_option( 'm365_client_secret', yourls_m365_post_string( 'client_secret' ) );
    }
    if( !yourls_m365_setting_is_locked( 'allowed_groups' ) ) {
        yourls_update_option( 'm365_allowed_groups', yourls_m365_post_string( 'allowed_groups' ) );
    }
    yourls_update_option( 'm365_button_label', yourls_m365_post_string( 'button_label' ) );

    // Config changed: drop any cached signing keys so a tenant switch takes effect immediately
    yourls_delete_option( 'm365_jwks_cache' );

    yourls_add_notice( yourls__( 'Microsoft 365 login settings saved.' ) );
}

function yourls_m365_settings_page() {
    $tenant_id       = (string) yourls_get_option( 'm365_tenant_id', '' );
    $client_id       = (string) yourls_get_option( 'm365_client_id', '' );
    $has_secret      = (bool) yourls_get_option( 'm365_client_secret', '' );
    $allowed_groups  = (string) yourls_get_option( 'm365_allowed_groups', '' );
    $button_label    = (string) yourls_get_option( 'm365_button_label', '' );
    $redirect_uri    = yourls_m365_redirect_uri();
    ?>
    <h2><?php yourls_e( 'Microsoft 365 Login' ); ?></h2>

    <p><?php yourls_e( 'Lets people sign in to this admin area with their Microsoft 365 / Entra ID account. Local username/password logins configured in config.php keep working as a fallback.' ); ?></p>

    <h3><?php yourls_e( '1. Azure app registration' ); ?></h3>
    <p><?php yourls_e( 'In the Azure Portal, register an application under Entra ID &rarr; App registrations, then add a <strong>Web</strong> platform redirect URI set to exactly:' ); ?></p>
    <p><code style="user-select:all;"><?php echo yourls_esc_html( $redirect_uri ); ?></code></p>
    <p><?php yourls_e( 'Create a client secret under "Certificates &amp; secrets" and copy the Tenant ID, Application (client) ID and the secret value below.' ); ?></p>

    <h3><?php yourls_e( '2. Settings' ); ?></h3>
    <form method="post">
        <?php yourls_nonce_field( 'm365_settings', 'yourls_m365_nonce' ); ?>
        <table class="tblSorter">
            <tr>
                <td><label for="m365_tenant_id"><?php yourls_e( 'Tenant ID' ); ?></label></td>
                <td>
                    <?php if( yourls_m365_setting_is_locked( 'tenant_id' ) ): ?>
                        <input type="text" value="<?php echo yourls_esc_attr( yourls_m365_get_setting( 'tenant_id' ) ); ?>" class="text" disabled="disabled" />
                        <p><em><?php yourls_e( 'Defined in config.php as YOURLS_M365_TENANT_ID.' ); ?></em></p>
                    <?php else: ?>
                        <input type="text" name="tenant_id" id="m365_tenant_id" value="<?php echo yourls_esc_attr( $tenant_id ); ?>" class="text" placeholder="contoso.onmicrosoft.com" />
                    <?php endif; ?>
                </td>
            </tr>
            <tr>
                <td><label for="m365_client_id"><?php yourls_e( 'Application (client) ID' ); ?></label></td>
                <td>
                    <?php if( yourls_m365_setting_is_locked( 'client_id' ) ): ?>
                        <input type="text" value="<?php echo yourls_esc_attr( yourls_m365_get_setting( 'client_id' ) ); ?>" class="text" disabled="disabled" />
                        <p><em><?php yourls_e( 'Defined in config.php as YOURLS_M365_CLIENT_ID.' ); ?></em></p>
                    <?php else: ?>
                        <input type="text" name="client_id" id="m365_client_id" value="<?php echo yourls_esc_attr( $client_id ); ?>" class="text" />
                    <?php endif; ?>
                </td>
            </tr>
            <tr>
                <td><label for="m365_client_secret"><?php yourls_e( 'Client secret' ); ?></label></td>
                <td>
                    <?php if( yourls_m365_setting_is_locked( 'client_secret' ) ): ?>
                        <input type="password" value="********" class="text" disabled="disabled" />
                        <p><em><?php yourls_e( 'Defined in config.php as YOURLS_M365_CLIENT_SECRET.' ); ?></em></p>
                    <?php else: ?>
                        <input type="password" name="client_secret" id="m365_client_secret" value="" class="text" autocomplete="new-password" placeholder="<?php echo $has_secret ? yourls_esc_attr__( 'Leave blank to keep the current secret' ) : ''; ?>" />
                    <?php endif; ?>
                </td>
            </tr>
            <tr>
                <td><label for="m365_allowed_groups"><?php yourls_e( 'Allowed Entra ID group(s)' ); ?></label></td>
                <td>
                    <?php if( yourls_m365_setting_is_locked( 'allowed_groups' ) ): ?>
                        <input type="text" value="<?php echo yourls_esc_attr( yourls_m365_get_setting( 'allowed_groups' ) ); ?>" class="text" disabled="disabled" />
                        <p><em><?php yourls_e( 'Defined in config.php as YOURLS_M365_ALLOWED_GROUPS.' ); ?></em></p>
                    <?php else: ?>
                        <input type="text" name="allowed_groups" id="m365_allowed_groups" value="<?php echo yourls_esc_attr( $allowed_groups ); ?>" class="text" placeholder="00000000-0000-0000-0000-000000000000" />
                    <?php endif; ?>
                    <p><em>
                        <?php yourls_e( 'Group <strong>Object ID</strong> (a GUID), not the group name -- find it under Entra ID &rarr; Groups &rarr; (your group) &rarr; Overview. Comma-separated for more than one group.' ); ?>
                        <?php yourls_e( 'Requires enabling group claims once for this app: Entra ID &rarr; App registrations &rarr; your app &rarr; <strong>Token configuration</strong> &rarr; Add groups claim &rarr; check "Security groups" for the ID token.' ); ?>
                        <?php yourls_e( 'Note: Microsoft omits the groups claim if an account belongs to too many groups (~200+, tenant-wide); use a small dedicated group rather than a huge one.' ); ?>
                    </em></p>
                </td>
            </tr>
            <tr>
                <td><label for="m365_button_label"><?php yourls_e( 'Login button text' ); ?></label></td>
                <td><input type="text" name="button_label" id="m365_button_label" value="<?php echo yourls_esc_attr( $button_label ); ?>" class="text" placeholder="<?php yourls_esc_attr_e( 'Sign in with Microsoft 365' ); ?>" /></td>
            </tr>
        </table>
        <p><em><?php yourls_e( 'An allowed group must be set, otherwise no Microsoft 365 account will be able to sign in.' ); ?></em></p>
        <p><input type="submit" class="button" value="<?php yourls_esc_attr_e( 'Save changes' ); ?>" /></p>
    </form>
    <?php
}
