<?php
/**
 * Replaces the default Silverstripe {@link Security} controller class
 * 
 * @package silverstripe-saml-sp
 * @author Shoaib Ali <shoaib@catalyst.net.nz>
 */
class SAMLSecurity extends Controller {

	/**
	 * This holds the OneLogin_Saml2_Auth object with the config
	 * from the Identity Provider data object
	 * @var mixed
	 */
	private static $authenticator;

	/**
	 * Force HTTPS mode when executing authentication functions
	 * @var boolean
	 */
	private static $force_ssl = false; 
	
	private static $allowed_actions = array( 
		'ping',
		'metadata',
		'acs',
		'sls',
		'index',
		'login',
		'logout', 
		'loggedout'
	);

	public function init() {
		parent::init();

		// I am not sure if this is a good idea but it will always take the first
		// active Identity Provider. 
		// More identity providers can be added in future for oAuth (Facebook, Twitter etc)

		$IdPsettingsInfo = IdentityProvider::get()->filter('Active', '1')->First();
		
		if(!empty($settingsInfo)) {
			user_error("No IdP Available or Active, Please go to CMS/SAML tab and define an Identity Provder", E_USER_ERROR);
		}

		$SPsettingsInfo = SiteConfig::current_site_config();


		$settingsInfo = array (
			'strict' => $SPsettingsInfo->StrictMode,
			'debug' => $SPsettingsInfo->Debug,
			'sp' => array (
				'entityId' => $SPsettingsInfo->SPEntityID,
				'assertionConsumerService' => array (
					'url' => $SPsettingsInfo->ACSurl,
					'binding' => $SPsettingsInfo->ACSbinding,
				),
				'singleLogoutService' => array (
					'url' => $SPsettingsInfo->SLSurl,
					'binding' => $SPsettingsInfo->SLSbinding,
				),
				'NameIDFormat' => $SPsettingsInfo->NameIDFormat,
				'x509cert' => $SPsettingsInfo->x509cert,
				'privateKey' > $SPsettingsInfo->privateKey,
			),

			// Identity Provider Data that we want connect with our SP
			'idp' => array (
				'entityId' => $IdPsettingsInfo->entityid,
				'singleSignOnService' => array (
					'url' => $IdPsettingsInfo->singleSignOnServiceUrl,
					'binding' => $IdPsettingsInfo->singleSignOnServiceBinding ,
				),
				'singleLogoutService' => array (
					'url' => $IdPsettingsInfo->singleLogoutServiceUrl,
					'binding' => $IdPsettingsInfo->singleLogoutServiceBinding,
				),
				'x509cert' => $IdPsettingsInfo->x509cert ,
				'certFingerprint' => $IdPsettingsInfo->certFingerprint,
			),
		);


		// initialize the SAML authenticator
		self::$authenticator = new OneLogin_Saml2_Auth($settingsInfo);
		// Prevent clickjacking, see https://developer.mozilla.org/en-US/docs/HTTP/X-Frame-Options
		$this->response->addHeader('X-Frame-Options', 'SAMEORIGIN');
	}

	public function index() {
		$this->forceSSL();		
		return $this->redirect(BASE_URL . 'Security/login');
	}

	public function metadata() {

		try {
			
			$settings = self::$authenticator->getSettings();
			$metadata = $settings->getSPMetadata();
			$errors = $settings->validateMetadata($metadata);
			if (empty($errors)) {
				header('Content-Type: text/xml');
				echo $metadata;
			} else {
				throw new OneLogin_Saml2_Error(
					'Invalid SP metadata: '.implode(', ', $errors),
					OneLogin_Saml2_Error::METADATA_SP_INVALID
				);
			}
		} catch (Exception $e) {
			user_error("SLS Error" . $e->getMessage(), E_USER_ERROR);
		}


	}
	
	/**
	 * Log the current user into the identity provider, and then Silverstripe
	 * @see OneLogin_Saml2_Auth->login()
	 */
	public function login() {
		$this->forceSSL();
		self::$authenticator->login('/Security/login');
	}


	/**
	 * Authenticate the user using attributes returned from IdP
	 * @see OneLogin_Saml2_Auth->getAttributes()
	 * @todo Handle user provisioning
	 */

	private function authenticate() {
		$attributes = self::$authenticator->getAttributes();
 		
 		// TODO Maybe look at storing this in class variable because it will be used 
 		// again and again for future enhancements. Currently being called again in init()
 		$spConfig = SiteConfig::current_site_config();

 		$AttributeMapID = $spConfig->AttributeMapID;
 		$FederationUID = $spConfig->FederationUID;


		$uid = $attributes[$AttributeMapID][0];
		$member = Member::get()->filter($FederationUID , $uid)->first();

		// TODO Mapping of extra attributes sent by IdP in to SilverStripe
		// TODO Handle account provisioning
		//If the member does not exist in Silverstripe, create them
		// if (!$member) {
		//     $member = new Member();
		//     $member->Username = $attributes['sAMAccountName'][0];
		//     $member->FirstName =  $attributes['givenName'][0];
		//     $member->Surname =  $attributes['sn'][0];
		//     $member->Email =  $attributes['mail'][0]; 
			
		//     $member->write();
		// }
		
		return $member;
	}
	
	/* Assertion Consumer Service */
	public function acs() {
		
		self::$authenticator->processResponse();
		$errors = self::$authenticator->getErrors();

		if (!empty($errors)) {
			user_error("SLS Error" . implode(', ', $errors), E_USER_ERROR);
		}

		if (! self::$authenticator->isAuthenticated()) {
			// TODO redirect back to login? or a page saying they need to initiate login again
			echo "<p>Not authenticated</p>";
			exit();
		}

		$member = $this->authenticate();

		if(!$member instanceof Member) {
			user_error(get_class($auth) . ' does not return a valid Member');
		}

		$member->login();
		
		//Use the BackURL for redirection if avaiable, or fall back on RelayState
		$dest = !empty(Session::get('BackURL')) ? Session::get('BackURL') : $this->request->postVar('RelayState');
		
		Session::clear('BackURL');
		
		return $this->redirect($dest);

	}

	/* Process the SAML Logout Response / Logout Request sent by the IdP. */
	public function sls() {
		self::$authenticator->processSLO();
		$errors = self::$authenticator->getErrors();
		if (empty($errors)) {
			$this->redirect('/Security/loggedout');
		} else {
			user_error("SLS Error" . implode(', ', $errors), E_USER_ERROR);
		}
	}

	/**
	 * SP initiated SLO process
	 * @see logout()
	 */

	public function slo() {
		$this->logout();
	}


	/**
	 * Log the currently logged in user out of the identity provider
	 * @see OneLogin_Saml2_Auth->logout()
	 */
	public function logout() {
		$this->forceSSL();
		
		self::$authenticator->logout(array(
			'ReturnTo' => '/Security/loggedout'
		));
	}

	/**
	* Log the currently logged in user out of the local Silverstripe website.
	* This function should only be called after logging out of the identity provider.
	*
	* @see logout()
	*/
	public function loggedout() {
		$this->forceSSL();
		
		//Log out Silverstripe members
		if($member = Member::currentUser()) {
			$member->logout();
		}
				
		//$this->sls();
		return $this->redirect(str_replace('https', 'http', Director::absoluteBaseURL()));
	}
	

	/**
	 * Forces HTTPS mode if set in the configuration
	 */
	private function forceSSL() {
		$mode = $this->config()->force_ssl;
		
		if(!is_bool($mode)) {
			user_error("Expected boolean in SAMLSecurity::force_ssl", E_USER_ERROR);
		}
		
		if($mode) {
			Director::forceSSL();
		}
	}
}