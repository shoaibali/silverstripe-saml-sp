<?php

if( Config::inst()->get('SingleSignOnConfig', 'EnableSingleSignOn') ) {
	Config::inst()->update('Director', 'rules', $rule = array('Security//$Action/$ID/$OtherID' => 'SAMLSecurity', 
															  'security//$Action/$ID/$OtherID' => 'SAMLSecurity'));
}