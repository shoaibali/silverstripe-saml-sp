<?php

class SingleSignOnConfig extends DataExtension {
	/**
	 * @var array
	 */
	private static $db = array(
		'SPEntityID' => "Varchar(255)",
		'ACSurl' => "Varchar(255)",
		'ACSbinding' => "Varchar(255)",
		'SLSurl' => "Varchar(255)",
		'SLSbinding' => "Varchar(255)",
		'NameIDFormat' => "Varchar(255)",
		'FederationUID' => "Varchar(255)",
		'AttributeMapID' => "Varchar(255)",
		'x509cert' => "Text", // Certs and Private key should not be in Database
		'privatekey' => "Text",
		'StrictMode' => "Boolean",
		'Debug' => "Boolean", // @TODO This should be true in development environment
		'IdPnameIdEncrypted' => "Boolean",
		'authnRequestsSigned' => "Boolean",
		'logoutRequestSigned' => "Boolean",
		'logoutResponseSigned' => "Boolean",
		'signMetadata' => "Boolean",	// @TODO False || True (use sp certs) || array(keyFileName, certFileName)
		'wantMessagesSigned' => "Boolean",
		'wantAssertionsSigned' => "Boolean",
		'wantNameIdEncrypted' => "Boolean",
		'requestedAuthnContext' => "Boolean(1)", // @TODO add array support see php-saml advance settings
		'ContactPersonTechnicalName' => "Varchar",
		'ContactPersonTechnicalEmail' => "Varchar",
		'ContactPersonSupportName' => "Varchar",
		'ContactPersonSupportEmail' => "Varchar",
		'OrganisationName' => "Varchar",
		'OrganisationDisplayName' => "Varchar",
		'OrganisationUrl' => "Varchar",
	);

	public function requireDefaultRecords() {
		// assemble the default values
		$defaults = array(
			'SPEntityID' => Director::absoluteBaseURL(),
			'ACSurl' => Director::absoluteBaseURL() . 'Security/acs',
			'ACSbinding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
			'SLSurl' => Director::absoluteBaseURL() . 'Security/sls',
			'SLSbinding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
			'NameIDFormat' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
			'FederationUID' => 'Email',
			'AttributeMapID' => 'mail',
		);

		$config = SiteConfig::current_site_config();

		$ensureHasContent = array_keys($defaults);
		foreach ($ensureHasContent as $item) {
			if (!$config->$item) $config->$item = $defaults[$item];
		}

		$config->write();
	}

	/**
	 * assemble the form for the CMS
	 *
	 * @param FieldList $fields
	 */
	public function updateCMSFields(FieldList $fields) {
		if (!Config::inst()->get('SingleSignOnConfig', 'EnableSingleSignOn')) {
			$fields->addFieldToTab('Root.SingleSignOn', new FieldGroup(
				_t('SSO_ENABLED', 'SSO Enabled'),
				new LiteralField(
					_t('SSO_ENABLED_LONG', 'Single Sign On Enabled'),
					_t(
						'SSO_DISABLED_MSG',
						'No - Please check _config.yml for EnableSingleSignOn: true'
					)
				)
			));
		} else {
			$fields->addFieldToTab(
				'Root.SingleSignOn',
				new TextField("SPEntityID", _t('SPEntityID', 'Entity ID'))
			);
			$fields->addFieldToTab(
				'Root.SingleSignOn',
				new TextField("ACSurl", _t('ACSurl', 'ACSurl'))
			);
			$fields->addFieldToTab(
				'Root.SingleSignOn',
				new TextField("ACSbinding", _t('ACSbinding', 'ACSbinding'))
			);
			$fields->addFieldToTab(
				'Root.SingleSignOn',
				new TextField("SLSurl", _t('SLSurl', 'SLSurl'))
			);
			$fields->addFieldToTab(
				'Root.SingleSignOn',
				new TextField("SLSbinding", _t('SLSbinding', 'SLSbinding'))
			);
			$fields->addFieldToTab(
				'Root.SingleSignOn',
				new TextField("NameIDFormat", _t('NameIDFormat', 'NameIDFormat'))
			);

			$fields->addFieldToTab('Root.SingleSignOn', new FieldGroup(
				"Federation",
				new TextField(
					"FederationUID",
					_t('FederationUID', 'SilverStripe Member column')
				),
				new TextField(
					"AttributeMapID",
					_t('AttributeMapID', 'Attribute from IdP Mapped to SilverStripe Member')
				)
			));

			$fields->addFieldToTab(
				'Root.SingleSignOn',
				new TextAreaField("x509cert", _t('x509cert', 'x509 Cert'))
			);
			$fields->addFieldToTab(
				'Root.SingleSignOn',
				new TextAreaField("privatekey", _t('privatekey', 'Private Key'))
			);

			$fields->addFieldToTab('Root.SingleSignOn', new FieldGroup(
				_t('SPMETADATA', "SP Metadata"),
				new LiteralField(
					_t('METADATAURL', "Metadata URL"),
					_t(
						'METADATAURL_MSG',
						'<a href="{url}" target="_blank">{url}</a>',
						array('URL' => Director::absoluteBaseURL() . 'Security/metadata')
					)
				)
			));

			$fields->addFieldToTab('Root.SingleSignOn', new FieldGroup(
				_t('StrictMode', 'Strict mode'),
				new CheckboxField(
					"StrictMode",
					_t(
						'STRICTMODE_MSG',
						'Strict mode - If \'strict\' is True, then the PHP Toolkit will reject ' .
						'unsigned or unencrypted messages if it expects them signed or encrypted.' .
						'Also will reject the messages if not strictly follow the SAML.'
					)
				)
			));

			$fields->addFieldToTab('Root.SingleSignOn', new FieldGroup(
				_t('DEBUG', 'Debug'),
				new CheckboxField("Debug", "Enable debug mode (to print errors)")));
			$fields->addFieldToTab('Root.SingleSignOn', new FieldGroup(
				_t('ENCRYPT_NAMEID', 'Encrypt NameID'),
				new CheckboxField(
					'IdPnameIdEncrypted',
					_t(
						'IdPnameIdEncrypted',
						'Indicates that the nameID of the <samlp:logoutRequest> sent by this SP ' .
						'will be encrypted.'
					)
				)
			));

			$fields->addFieldToTab('Root.SingleSignOn', new FieldGroup(
				_t('SIGN_AUTHNREQUEST', 'Sign AuthnRequest'),
				new CheckboxField(
					'authnRequestsSigned',
					_t(
						'authnRequestsSigned',
						'Indicates whether the <samlp:AuthnRequest> messages sent by this SP ' .
						'will be signed.'
					)
				)
			));

			$fields->addFieldToTab('Root.SingleSignOn', new FieldGroup(
				_t('SIGN_LOGOUT_REQUEST', 'Sign Logout Request'),
				new CheckboxField(
					'logoutRequestSigned',
					_t(
						'logoutRequestSigned',
						'Indicates whether the <samlp:logoutRequest> messages sent by this SP ' .
						'will be signed.'
					)
				)
			));

			$fields->addFieldToTab('Root.SingleSignOn', new FieldGroup(
				_t('SIGN_LOGOUT_RESPONSE', 'Sign Logout Response'),
				new CheckboxField(
					'logoutResponseSigned',
					_t(
						'logoutResponseSigned',
						'Indicates whether the <samlp:logoutResponse> messages sent by this SP ' .
						'will be signed.'
					)
				)
			));

			$fields->addFieldToTab('Root.SingleSignOn', new FieldGroup(
				_t('SIGN_METADATA', 'Sign Metadata'),
				new CheckboxField(
					'signMetadata',
					_t(
						'signMetadata',
						'It will use cert files keyFileName => metadata.key, certFileName => ' .
						'metadata.crt'
					)
				)
			));

			$fields->addFieldToTab('Root.SingleSignOn', new FieldGroup(
				_t('REQUIRE_SIGNED_MESSAGES', 'Require Signed Messages'),
				new CheckboxField(
					'wantMessagesSigned',
					_t(
						'wantMessagesSigned',
						'Indicates a requirement for the <samlp:Response>, <samlp:LogoutRequest> ' .
						'and <samlp:LogoutResponse> elements received by this SP to be signed.'
					)
				)
			));

			$fields->addFieldToTab('Root.SingleSignOn', new FieldGroup(
				_t('REQUIRE_SIGNED_ASSERTIONS', 'Require Signed Assertions'),
				new CheckboxField(
					'wantAssertionsSigned',
					_t(
						'wantAssertionsSigned',
						'Indicates a requirement for the <saml:Assertion> elements received by ' .
						'this SP to be signed.'
					)
				)
			));

			$fields->addFieldToTab('Root.SingleSignOn', new FieldGroup(
				_t('REQUIRE_NAMEID_ENCRYPTED', 'Require NameID Encrypted'),
				new CheckboxField(
					'wantNameIdEncrypted',
					_t(
						'wantNameIdEncrypted',
						'Indicates a requirement for the NameID received by this SP to be encrypted.'
					)
				)
			));

			$fields->addFieldToTab('Root.SingleSignOn', new FieldGroup(
				_t('AUTHENTICATION_CONTEXT', 'Authentication Context'),
				new CheckboxField(
					'requestedAuthnContext',
					_t(
						'requestedAuthnContext',
						'Set to false and no AuthContext will be sent in the AuthNRequest. ' .
						'Set true or don\'t present this parameter and you will get an ' .
						'AuthContext \'exact\' ' .
						'\'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport\''
					)
				)
			));

			$fields->addFieldToTab('Root.SingleSignOn', new FieldGroup(
				_t('CONTACT_DETAILS', "Contact Details"),
				new TextField(
					"ContactPersonTechnicalName",
					_t('ContactPersonTechnicalName', 'Technical Contact Name')
				),
				new TextField(
					"ContactPersonTechnicalEmail",
					_t('ContactPersonTechnicalEmail', 'Technical Contact Email')
				),
				new TextField(
					"ContactPersonSupportName",
					_t('ContactPersonSupportName', 'Support Contact Name')
				),
				new TextField(
					"ContactPersonSupportEmail",
					_t('ContactPersonSupportEmail', 'Support Contact Email')
				)
			));

			$fields->addFieldToTab(
				'Root.SingleSignOn',
				new FieldGroup(_t('OrganisationName', 'Organisation Details'),
					new TextField("OrganisationName", _t('OrganisationName', 'Origanisation Name')),
					new TextField(
						"OrganisationDisplayName",
						_t('OrganisationDisplayName', 'Organisation Display Name')
					),
					new TextField("OrganisationURL", _t('OrganisationURL', 'Organisation URL'))
				)
			);
		}
	}
}