<?php

// @TODO re-routing should only work when it is enabled in config and there is an active IdP.
if (Config::inst()->get('SingleSignOnConfig', 'EnableSingleSignOn')) {
	// process all request of '/security' with the SAML controller.
	Config::inst()->update('Director', 'rules', array(
		'Security//$Action/$ID/$OtherID' => 'SAMLSecurity',
		'security//$Action/$ID/$OtherID' => 'SAMLSecurity'
	));
}

