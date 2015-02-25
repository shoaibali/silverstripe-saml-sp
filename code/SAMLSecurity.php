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
	 *
	 * @var OneLogin_Saml2_Auth
	 */
	private static $authenticator;


	/**
	 * Force HTTPS mode when executing authentication functions
	 *
	 * @var boolean
	 */
	private static $force_ssl = false;

	/**
	 * @var array
	 */
	private static $allowed_actions = array(
		'ping',
		'metadata',
		'acs',
		'sls',
		'index',
		'login',
		'logout',
		'loggedout',
	);

	public function init() {
		parent::init();

		// More identity providers can be added in future for oAuth (Facebook, Twitter etc).
		// Here we use the first active by default as there shouldn't be more than one active.
		$IdPsettings = IdentityProvider::get()->filter('Active', '1')->First();

		// When configured correctly this should never be the case. Just for security.
		if(empty($IdPsettings)) {
			// @TODO move to translation file.
			user_error(
				_t(
					'NO_IDP_ACTIVE',
					'No IdP Available or Active. Please define and activate an Identity Provder.'
				),
				E_USER_ERROR
			);
		}

		$SPsettings = SiteConfig::current_site_config();

		// assemble the settings
		$settings = array(
			'strict' => $SPsettings->StrictMode,
			'debug' => $SPsettings->Debug,
			'sp' => array(
				'entityId' => $SPsettings->SPEntityID,
				'assertionConsumerService' => array(
					'url' => $SPsettings->ACSurl,
					'binding' => $SPsettings->ACSbinding,
				),
				'singleLogoutService' => array(
					'url' => $SPsettings->SLSurl,
					'binding' => $SPsettings->SLSbinding,
				),
				'NameIDFormat' => $SPsettings->NameIDFormat,
				'x509cert' => $SPsettings->x509cert,
				'privateKey' > $SPsettings->privateKey,
			),

			// Identity Provider Data that we want connect with our SP
			'idp' => array(
				'entityId' => $IdPsettings->entityid,
				'singleSignOnService' => array(
					'url' => $IdPsettings->singleSignOnServiceUrl,
					'binding' => $IdPsettings->singleSignOnServiceBinding,
				),
				'singleLogoutService' => array(
					'url' => $IdPsettings->singleLogoutServiceUrl,
					'binding' => $IdPsettings->singleLogoutServiceBinding,
				),
				'x509cert' => $IdPsettings->x509cert,
				'certFingerprint' => $IdPsettings->certFingerprint,
			),
		);

		// initialize the SAML authenticator
		self::$authenticator = new OneLogin_Saml2_Auth($settings);

		// Prevent clickjacking, see https://developer.mozilla.org/en-US/docs/HTTP/X-Frame-Options
		$this->response->addHeader('X-Frame-Options', 'SAMEORIGIN');
	}

	public function index() {
		$this->forceSSL();
		return $this->redirect(BASE_URL . 'Security/login');
	}

	/**
	 * gets the metadata and returns them as a xml
	 *
	 * @return SS_HTTPResponse
	 */
	public function metadata() {
		try {
			$settings = self::$authenticator->getSettings();
			$metadata = $settings->getSPMetadata();
			$errors = $settings->validateMetadata($metadata);

			if (empty($errors)) {
				$response = new SS_HTTPResponse($metadata);
				$response->addHeader('Content-Type', 'text/xml');
				return $response;
			} else {
				throw new OneLogin_Saml2_Error(
					'Invalid SP metadata: ' . implode(', ', $errors),
					OneLogin_Saml2_Error::METADATA_SP_INVALID
				);
			}
		} catch (Exception $e) {
			user_error(_t('SLS_ERROR', "SLS Error") . $e->getMessage(), E_USER_ERROR);
		}
	}

	/**
	 * Log the current user into the identity provider, and then Silverstripe
	 *
	 * @see OneLogin_Saml2_Auth->login()
	 */
	public function login() {
		$this->forceSSL();
		self::$authenticator->login('/Security/login');
	}

	/**
	 * Authenticate the user using attributes returned from IdP
	 *
	 * @see OneLogin_Saml2_Auth->getAttributes()
	 * @todo Handle user provisioning
	 */
	private function authenticate() {
		// load the config to get the mapping of the keys provided by the IdP into
		//  SilverStripe member-class fields
		$spConfig = SiteConfig::current_site_config();
		$AttributeMapID = $spConfig->AttributeMapID;
		$FederationUID = $spConfig->FederationUID;

		// Extract the UID out of the response
		$attributes = self::$authenticator->getAttributes();
		$uid = $attributes[$AttributeMapID][0];

		// load the member based on the provided UID (usually the mail address)
		$member = Member::get()->filter($FederationUID, $uid)->first();

		/*
		 * @Note: Currently a existing account within SilverStripe is required.
		 * If you want to create members on the fly you can do this here.
		 */

		return $member;
	}


	/**
	 * Assertion Consumer Service
	 *
	 * @return SS_HTTPResponse
	 */
	public function acs() {
		self::$authenticator->processResponse();
		$errors = self::$authenticator->getErrors();

		if (!empty($errors)) {
			user_error(_t('SLS_ERROR', "SLS Error") . implode(', ', $errors), E_USER_ERROR);
		}

		// if the user isn't logged in send him back to the IdP
		if (!self::$authenticator->isAuthenticated()) {
			return $this->redirect('/security/login');
		}

		$member = $this->authenticate();

		if(!$member instanceof Member) {
			user_error(_t(
				'NOT_A_VALID_MEMBER',
				'{class} does not return a valid Member',
				array('class' => get_class($auth))
			));
		}

		$member->login();

		// Use the BackURL for redirection if avaiable, or fall back on RelayState
		$dest = Session::get('BackURL');
		if (!empty($backURL)) $dest = $this->request->postVar('RelayState');
		Session::clear('BackURL');

		return $this->redirect($dest);
	}

	/**
	 * Process the SAML Logout Response / Logout Request sent by the IdP.
	 *
	 * @return SS_HTTPResponse
	 */
	public function sls() {
		self::$authenticator->processSLO();
		$errors = self::$authenticator->getErrors();

		if (empty($errors)) {
			return $this->redirect('/Security/loggedout');
		} else {
			user_error(_t('SLS_ERROR', "SLS Error") . implode(', ', $errors), E_USER_ERROR);
		}
	}

	/**
	 * SP initiated SLO process
	 *
	 * @see logout()
	 */
	public function slo() {
		return $this->logout();
	}


	/**
	 * Log the currently logged in user out of the identity provider
	 *
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

		// Log out Silverstripe members
		if($member = Member::currentUser()) {
			$member->logout();
		}

		// @TODO where to end up really?
		return $this->redirect(Director::absoluteBaseURL());
	}

	/**
	 * Forces HTTPS mode if set in the configuration
	 */
	private function forceSSL() {
		$mode = $this->config()->force_ssl;

		if (!is_bool($mode)) {
			user_error(
				_t(
					'ERROR_NOT_A_BOOLEAN',
					'Expected boolean in SAMLSecurity::force_ssl'
				),
				E_USER_ERROR
			);
		}

		if ($mode) {
			Director::forceSSL();
		}
	}
}