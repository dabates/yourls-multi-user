<?php
if ( !defined( 'YOURLS_MULTIUSER_PROTECTED' ) ) {
    define( 'YOURLS_MULTIUSER_PROTECTED', true );
}

if ( !defined( 'YOURLS_DB_TABLE_USERS' ) ) {
    define( 'YOURLS_DB_TABLE_USERS', YOURLS_DB_PREFIX . "users" );
}

if ( !defined( 'YOURLS_DB_TABLE_URL_TO_USER' ) ) {
    define( 'YOURLS_DB_TABLE_URL_TO_USER', YOURLS_DB_PREFIX . 'url_to_user' );
}

if ( !defined( 'YOURLS_MULTIUSER_CAPTCHA' ) ) {
    define( 'YOURLS_MULTIUSER_CAPTCHA', false );
}

if ( !defined( 'YOURLS_MULTIUSER_CAPTCHA_PUBLIC_KEY' ) && !defined( 'YOURLS_MULTIUSER_CAPTCHA' ) ) {
    define( 'YOURLS_MULTIUSER_CAPTCHA', false );
}

if ( !defined( 'YOURLS_MULTIUSER_CAPTCHA_PRIVATE_KEY' ) && !defined( 'YOURLS_MULTIUSER_CAPTCHA' ) ) {
    define( 'YOURLS_MULTIUSER_CAPTCHA', false );
}

if ( !defined( 'YOURLS_MULTIUSER_CAPTCHA_THEME' ) ) {
    define( 'YOURLS_MULTIUSER_CAPTCHA_THEME', 'white' );
}

if ( !defined( 'YOURLS_MULTIUSER_ANONYMOUS' ) ) {
    define( 'YOURLS_MULTIUSER_ANONYMOUS', true );
}

if ( !defined( 'YOURLS_MULTIUSER_LDAP_HOST' ) ) {
    define( 'YOURLS_MULTIUSER_LDAP', false );
}

if ( !defined( 'YOURLS_MULTIUSER_LDAP_PORT' ) && !defined( 'YOURLS_MULTIUSER_LDAP' ) ) {
    define( 'YOURLS_MULTIUSER_LDAP', false );
}

if ( !defined( 'YOURLS_MULTIUSER_LDAP_USERBASEDN' ) && !defined( 'YOURLS_MULTIUSER_LDAP' ) ) {
    define( 'YOURLS_MULTIUSER_LDAP', false );
}

if ( !defined( 'YOURLS_MULTIUSER_LDAP_GROUPNAME' ) ) {
    define( 'YOURLS_MULTIUSER_LDAP_RESTRICT', false );
}

if (!defined('YOURLS_MULTIUSER_USE_PROXY_SCRIPT')) {
    define('YOURLS_MULTIUSER_USE_PROXY_SCRIPT', false);
}

function captchaEnabled()
{
    if ( defined( 'YOURLS_MULTIUSER_CAPTCHA' ) && ( YOURLS_MULTIUSER_CAPTCHA == true ) )
        return true;
    return false;
}


//http://www.linuxjournal.com/article/9585?page=0,3
/**
 * Validate an email address.
 * Provide email address (raw input)
 * Returns true if the email address has the email
 * address format and the domain exists.
 */
function validEmail( $email )
{
    $isValid = true;
    $atIndex = strrpos( $email, "@" );
    if ( is_bool( $atIndex ) && !$atIndex ) {
        $isValid = false;
    } else {
        $domain    = substr( $email, $atIndex + 1 );
        $local     = substr( $email, 0, $atIndex );
        $localLen  = strlen( $local );
        $domainLen = strlen( $domain );
        if ( $localLen < 1 || $localLen > 64 ) {
            // local part length exceeded
            $isValid = false;
        } else if ( $domainLen < 1 || $domainLen > 255 ) {
            // domain part length exceeded
            $isValid = false;
        } else if ( $local[0] == '.' || $local[ $localLen - 1 ] == '.' ) {
            // local part starts or ends with '.'
            $isValid = false;
        } else if ( preg_match( '/\\.\\./', $local ) ) {
            // local part has two consecutive dots
            $isValid = false;
        } else if ( !preg_match( '/^[A-Za-z0-9\\-\\.]+$/', $domain ) ) {
            // character not valid in domain part
            $isValid = false;
        } else if ( preg_match( '/\\.\\./', $domain ) ) {
            // domain part has two consecutive dots
            $isValid = false;
        } else if
        ( !preg_match( '/^(\\\\.|[A-Za-z0-9!#%&`_=\\/$\'*+?^{}|~.-])+$/',
            str_replace( "\\\\", "", $local ) ) ) {
            // character not valid in local part unless
            // local part is quoted
            if ( !preg_match( '/^"(\\\\"|[^"])+"$/',
                str_replace( "\\\\", "", $local ) ) ) {
                $isValid = false;
            }
        }
        if ( $isValid && !( checkdnsrr( $domain, "MX" ) || checkdnsrr( $domain, "A" ) ) ) {
            // domain not found in DNS
            $isValid = false;
        }
    }
    return $isValid;
}

// GENERATE A RANDON TOKEN!
function createRandonToken()
{
    global $ydb;
    $ui      = uniqid( uniqid( "a", true ), true );
    $table   = YOURLS_DB_TABLE_USERS;
    $results = $ydb->get_results( "select user_email from `$table` where `user_token` = '$ui'" );
    if ( !empty( $results ) ) {
        return createRandonToken();
    } else {
        return str_replace( ".", "", $ui );
    }
}

function isValidUser( $user, $pass )
{
    global $ydb;
    $table         = YOURLS_DB_TABLE_USERS;
    $boguspass     = "XXXXXXXXXXXXXXXXXXXXXXXX";
    $allowed       = false;
    $authenticated = false;
    $authorized    = false;

    if ( YOURLS_MULTIUSER_LDAP ) {
        $ldapOptions = [
            'host'        => YOURLS_MULTIUSER_LDAP_HOST,
            'port'        => YOURLS_MULTIUSER_LDAP_PORT,
            'useStartTls' => false,
            'userBaseDN'  => YOURLS_MULTIUSER_LDAP_USERBASEDN,
        ];

        $ldapUser = "cn=" . $user . "," . $ldapOptions[ userBaseDN ];

        $ldapDS = ldap_connect( $ldapOptions[ host ] )
        or die( "Could not connect to {$ldapOptions[host]}" );

        $ldapBind = ldap_bind( $ldapDS, $ldapUser, $pass );

        if ( $ldapBind ) {
            /* we have a winner  */
            $authenticated = true;
            /* can they use the service based upon group membership */
            if ( !YOURLS_MULTIUSER_LDAP_RESTRICT ) {
                $authorized = true;
            } else {
                $ldapFilter        = "(cn=*$user*)";
                $ldapAttributes    = [ "mail", "memberof" ];
                $ldapSearchResults = ldap_Search( $ldapDS, $ldapUser, $ldapFilter );
                $ldapInfo          = ldap_get_entries( $ldapDS, $ldapSearchResults );

                foreach ( $ldapInfo[0]['memberof'] as $grp ) {
                    if ( $grp == YOURLS_MULTIUSER_LDAP_GROUPNAME ) {
                        $authorized = true;
                        break;
                    }
                }
            }

            /* Clean up ldap connection */
            ldap_unbind( $ldapDS );
            /* ldap_close( $ldapDS ); */
        } else {
            /* authentication failed */
            return false;
        }

        if ( $authenticated && $authorized ) {
            /* are they in the local database? */
            $results = $ydb->get_results( "select user_token from `$table` where `user_email` = '$user' AND user_password = '$boguspass'" );
            if ( empty( $results ) ) {
                /* user is not in the database, so insert them */
                $ydb->query( "insert into `$table` (user_email, user_password, user_token) values ('$user', '$boguspass', '" . createRandonToken() . "' )" );
            }
            return true;
        }
    } else {
        /* see if we have a local account  */
        $pass    = md5( $pass );
        $results = $ydb->get_results( "select user_token from `$table` where `user_email` = '$user' and `user_password` = '$pass'" );
        if ( !empty( $results ) ) {
            return true;
        }
    }
    return false;
}

function getUserTokenByEmail( $user )
{
    global $ydb;
    $table   = YOURLS_DB_TABLE_USERS;
    $results = $ydb->get_results( "select user_token from `$table` where `user_email` = '$user'" );
    if ( !empty( $results ) ) {
        return $results[0]->user_token;
    }
    return false;
}

function getUserIdByToken( $token )
{
    global $ydb;
    $table   = YOURLS_DB_TABLE_USERS;
    $results = $ydb->get_results( "select user_id from `$table` where `user_token` = '$token'" );
    if ( !empty( $results ) ) {
        return $results[0]->user_id;
    }
    return false;
}

function verifyUrlOwner( $keyword, $userId )
{
    global $ydb;
    if ( isAdmin() ) {
        return true;
    }

    $table   = YOURLS_DB_TABLE_URL_TO_USER;
    $results = $ydb->get_results( "select url_keyword from `$table` where `url_keyword` = '$keyword' AND users_user_id = '$userId'" );

    if ( isset( $results ) ) {
        return true;
    }
    return false;
}

// Add a link row
function mu_table_add_row( $keyword, $url, $title = '', $ip, $clicks, $timestamp )
{
    $keyword         = yourls_sanitize_string( $keyword );
    $display_keyword = htmlentities( $keyword );

    $url         = yourls_sanitize_url( $url );
    $display_url = htmlentities( yourls_trim_long_string( $url ) );
    $title_url   = htmlspecialchars( $url );

    $title         = yourls_sanitize_title( $title );
    $display_title = yourls_trim_long_string( $title );
    $title         = htmlspecialchars( $title );

    $id     = yourls_string2htmlid( $keyword ); // used as HTML #id
    $date   = date( 'M d, Y H:i', $timestamp + ( YOURLS_HOURS_OFFSET * 3600 ) );
    $clicks = number_format( $clicks, 0, '', '' );

    $shorturl = YOURLS_SITE . '/' . $keyword;
    $statlink = $shorturl . '+';
    if ( yourls_is_ssl() )
        $statlink = str_replace( 'http://', 'https://', $statlink );

    if ( $title ) {
        $display_link = "<a href=\"$url\" title=\"$title\">$display_title</a><br/><small><a href=\"$url\" title=\"$title_url\">$display_url</a></small>";
    } else {
        $display_link = "<a href=\"$url\" title=\"$title_url\">$display_url</a>";
    }

    $delete_link = yourls_nonce_url( 'delete-link_' . $id,
        yourls_add_query_arg( [ 'id' => $id, 'action' => 'delete', 'keyword' => $keyword ], muAdminUrl( 'admin-ajax.php' ) )
    );

    $edit_link = yourls_nonce_url( 'edit-link_' . $id,
        yourls_add_query_arg( [ 'id' => $id, 'action' => 'edit', 'keyword' => $keyword ], muAdminUrl( 'admin-ajax.php' ) )
    );


    $actions
             = <<<ACTION
<a href="$statlink" id="statlink-$id" title="Stats" class="button button_stats">Stats</a><a href="" id="share-button-$id" name="share-button" title="Share" class="button button_share" onclick="toggle_share('$id');return false;">Share</a><a href="$edit_link" id="edit-button-$id" name="edit-button" title="Edit" class="button button_edit" onclick="edit_link_display('$id');return false;">Edit</a><a href="$delete_link" id="delete-button-$id" name="delete-button" title="Delete" class="button button_delete" onclick="remove_link('$id');return false;">Delete</a>
ACTION;
    $actions = yourls_apply_filter( 'action_links', $actions, $keyword, $url, $ip, $clicks, $timestamp );

    $row
         = <<<ROW
<tr id="id-$id"><td id="keyword-$id" class="keyword"><a href="$shorturl">$display_keyword</a></td><td id="url-$id" class="url">$display_link</td><td id="timestamp-$id" class="timestamp">$date</td><td id="ip-$id" class="ip">$ip</td><td id="clicks-$id" class="clicks">$clicks</td><td class="actions" id="actions-$id">$actions<input type="hidden" id="keyword_$id" value="$keyword"/></td></tr>
ROW;
    $row = yourls_apply_filter( 'table_add_row', $row, $keyword, $url, $title, $ip, $clicks, $timestamp );

    return $row;
}

function muAdminUrl( $page = '' )
{
    $admin = YOURLS_SITE . '/user/plugins/multi-user/' . $page;

    if (YOURLS_MULTIUSER_USE_PROXY_SCRIPT  && stripos($page, 'index.php') !== false) {
        $admin = YOURLS_SITE . "/" . YOURLS_MULTIUSER_USE_PROXY_SCRIPT . substr($page, strpos($page, '?'));
    }

    if ( defined( 'YOURLS_ADMIN_SSL' ) && YOURLS_ADMIN_SSL) {
        $admin = str_replace( 'http:', 'https:', $admin );
    }

    return yourls_apply_filter( 'admin_url', $admin, $page );
}

function isLogged()
{
    return ( !empty( $_SESSION['user'] ) && isset( $_SESSION['user'] ));
}

function isAdmin()
{
    global $yourls_multiuser_admin_users;

    if ( !empty( $_SESSION['user'] ) && isset( $_SESSION['user'] ) ) {
        foreach ( $yourls_multiuser_admin_users as $admin ) {
            if ( ( $_SESSION['user']['user'] ) == $admin ) {
                return true;
            }
        }
    }
    return false;
}
