<?php
/*
Plugin Name: Google Login
Description: Google OAuth2 login integration.
Version: 1.0
Author: Gal Adany
*/

// Define the site URL and domain only once
$site_url = get_site_url(); // https://new.galadany.com
$parsed_url = parse_url($site_url);
$domain = $parsed_url['host']; // new.galadany.com

// Google Login
$googleClientId = 'GOOGLE_CLIENT_ID';
$googleClientSecret = 'GOOGLE_CLIENT_SECRET';
$googleRedirectUri = $site_url;
$googleLoginUrl = 'https://accounts.google.com/o/oauth2/auth?client_id=' . $googleClientId . '&redirect_uri=' . urlencode($googleRedirectUri) . '&response_type=code&scope=email%20profile&approval_prompt=force';


// Shortcode for displaying login links
function google_social_login_shortcode() {
    global $googleLoginUrl;

    $output = '<li class="google-btn"><a href="'.$googleLoginUrl.'">
                    <div class="sicon">
                    <img src="/wp-content/uploads/2024/03/google.svg"> 
                    </div>
                    <div class="sname">
                    Google
                    </div>
                    </a></li>';
    return $output;
}
add_shortcode('google_social_login', 'google_social_login_shortcode');

// Handle callback from Google
function handle_google_callback() {

    global $site_url;

    if (isset($_GET['code'])) {
        $code = $_GET['code'];

        $googleClientId = 'GOOGLE_CLIENT_ID';
		$googleClientSecret = 'GOOGLE_CLIENT_SECRET';
		$googleRedirectUri = $site_url;
		        
        $token_request_data = array(
            'code' => $code,
            'client_id' => $googleClientId,
            'client_secret' => $googleClientSecret,
            'redirect_uri' => $googleRedirectUri,
            'grant_type' => 'authorization_code'
        );

        // Make a POST request to exchange code for access token
        $token_request_url = 'https://oauth2.googleapis.com/token';
        $token_response = wp_remote_post($token_request_url, array(
            'body' => $token_request_data,
            'sslverify' => false, // Depending on your server setup, you might need to set it to true or false
        ));

        if (is_wp_error($token_response)) {
            // Handle error
            return;
        }

        $token_body = wp_remote_retrieve_body($token_response);
        $token_info = json_decode($token_body, true);

        if (isset($token_info['error'])) {
            // Handle error
            return;
        }

        // Get user info using access token
        $access_token = $token_info['access_token'];
        $user_info_url = 'https://www.googleapis.com/oauth2/v2/userinfo?access_token=' . $access_token;
        $user_info_response = wp_remote_get($user_info_url);

        if (is_wp_error($user_info_response)) {
            // Handle error
            return;
        }

        $user_info_body = wp_remote_retrieve_body($user_info_response);
        $user_info = json_decode($user_info_body, true);

        if (!$user_info || isset($user_info['error'])) {
            // Handle error
            return;
        }

        // Process user info or do other necessary actions
        $user_email = $user_info['email'];
        $user = get_user_by('email', $user_email);

        // If user doesn't exist, register them
        if (!$user) {
            $username = $user_info['given_name'] . '-' . $user_info['family_name']; // Generate username from Google name
            $user_id = wp_create_user($username, wp_generate_password(), $user_email);
            
            update_user_meta($user_id, 'first_name', $user_info['given_name']);
            update_user_meta($user_id, 'last_name', $user_info['family_name']);
            update_user_meta($user_id, 'email_verified', 1);


            if (!is_wp_error($user_id)) {
                $user = get_user_by('id', $user_id);
            }
        }

        // If user found, log them in
        if ($user) {
        	
            if (!empty($_COOKIE['mailchimp_added']) && $_COOKIE['mailchimp_added'] === 'true') {

                $log_file = ABSPATH . 'user_login_google.log';
                $added = add_subscriber_to_mailchimp($user_email);
                error_log($added, 3, $log_file);

            }

            check_and_remove_purchased_items_after_login($user->ID);
            wp_set_auth_cookie($user->ID, true);
            wp_redirect(home_url());
            exit;
            
        }
    }
}

add_action('init', 'handle_google_callback');