Modifications since 1.7beta
---
####1.7.5beta
- Fixed some issues in `mufunctions.php` that was trying to redefine some already defined constants
- Fixed an issue where `$ydb` was not getting init'd before use
- Fixed an issue where the code was using a string instead of a array for the PDO function in `admin.php`
- Cleaned up some styling so that it's more in line with YOURLS coding standard

yourls-multi-user plugin
~~~~~~~~~~~~~~~~~~~~~~~~

This is a modification of the multi-user 1.7 beta yourls plugin created by Matheus (X-warrior) Bratfisch.  The original can be found:

http://www.matbra.com/en/code/multi-user-yourls-plugin/

The plugin was updated to use LDAP for authentication, and to cleanup some interface issues.

A plugin for YOURLS that allow multi users in the system

How it works:
Enabling this plugin it will be created two new tables in your data base. One to user registers and other to record what URL is from what user. The plugin allow public or private (owner and admin) access to statistics. The user when creates a new shortned link can change it and remove it. (not recommended becaause urls already published will become not valid.)

How to install:
- Copy plugin files to /user/plugins/multi-user/ folder.
- Access the administration area and activate the plugin.
- To access user pages use yoursite.com/your-yourls/user/plugins/multi-user (create a link in homepage is highly recommended)

Setup:
If you want something different than default setup, achange your config file.
YOURLS_MULTIUSER_PROTECTED - TRUE/FALSE - Stats is private to admin and owners of shortned links.
YOURLS_DB_TABLE_URL_TO_USER - Specific the name of database table to be used as URL to USER table.
YOURLS_DB_TABLE_USERS - Specific the name of the database table to be user as USERS table.
YOURLS_MULTIUSER_CAPTCHA - Enable user CAPTCHA to Sign in.
YOURLS_MULTIUSER_CAPTCHA_PUBLIC_KEY - Public API Key to Recaptcha, get yours: https://www.google.com/recaptcha/admin/create
YOURLS_MULTIUSER_CAPTCHA_PRIVATE_KEY - Private API Key to Recaptcha.
YOURLS_MULTIUSER_CAPTCHA_THEME - ReCAPTCHA theme.
YOURLS_MULTIUSER_ANONYMOUS - True if Anonymous user can shorturl, false if just logged users can shorturl.
$yourls_multiuser_admin_users - array of usernames that have administrative privileges, can be either local or LDAP accounts
YOURLS_MULTIUSER_LDAP - TRUE/FALSE - use LDAP for authentication
YOURLS_MULTIUSER_LDAP_HOST - hostname of the LDAP server
YOURLS_MULTIUSER_LDAP_PORT - port for LDAP connection ( typicall LDAP=389, LDAPS=636 )
YOURLS_MULTIUSER_LDAP_USERBASEDN - the baseDN in LDAP to begin looking for users
YOURLS_MULTIUSER_LDAP_RESTRICT - TRUE/FALSE - restrict logins to a particular group of users
YOURLS_MULTIUSER_LDAP_GROUPNAME - the LDAP group name of the group os users allowed to login 


It may also prove to be useful to add a short URL for the keyword login that points to http://<sitefqdn>/user/plugins/multi-user .
