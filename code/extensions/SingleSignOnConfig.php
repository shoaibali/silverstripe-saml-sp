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
			if(!$config->$item) $config->$item = $defaults[$item];
		}

		$config->write();
	}

	public function updateCMSFields(FieldList $fields) {
		// @TODO move text strings to the translation file. This should bring the lines under 100 char
		if (!Config::inst()->get('SingleSignOnConfig', 'EnableSingleSignOn')) {
			$fields->addFieldToTab("Root.SingleSignOn", new FieldGroup("SSO Enabled", new LiteralField("Sigle Sign On Enabled", "No - Please check _config.yml for EnableSingleSignOn: true" )));
		} else {
			$fields->addFieldToTab("Root.SingleSignOn", new TextField("SPEntityID", "Entity ID"));
			$fields->addFieldToTab("Root.SingleSignOn", new TextField("ACSurl", "ACSurl"));
			$fields->addFieldToTab("Root.SingleSignOn", new TextField("ACSbinding", "ACSbinding"));
			$fields->addFieldToTab("Root.SingleSignOn", new TextField("SLSurl", "SLSurl"));
			$fields->addFieldToTab("Root.SingleSignOn", new TextField("SLSbinding", "SLSbinding"));
			$fields->addFieldToTab("Root.SingleSignOn", new TextField("NameIDFormat", "NameIDFormat"));

			$fields->addFieldToTab("Root.SingleSignOn", new FieldGroup("Federation", new TextField("FederationUID", "SilverStripe Member column"),  new TextField("AttributeMapID", "Attribute from IdP Mapped to SilverStripe Member")));

			$fields->addFieldToTab("Root.SingleSignOn", new TextAreaField("x509cert", "x509cert"));
			$fields->addFieldToTab("Root.SingleSignOn", new TextAreaField("privatekey", "privatekey"));

			$fields->addFieldToTab("Root.SingleSignOn", new FieldGroup("SP Metadata", new LiteralField("Metadata URL", "<a href='" . Director::absoluteBaseURL() . "Security/metadata" ."' target='_blank'>" .  Director::absoluteBaseURL() . "Security/metadata" . "</a>")));

			$fields->addFieldToTab("Root.SingleSignOn", new FieldGroup("Strict mode", new CheckboxField("StrictMode", "Strict mode -  If 'strict' is True, then the PHP Toolkit will reject unsigned or unencrypted messages if it expects them signed or encrypted. Also will reject the messages if not strictly follow the SAML.")));

			$fields->addFieldToTab("Root.SingleSignOn", new FieldGroup("Debug", new CheckboxField("Debug", "Enable debug mode (to print errors)")));
			$fields->addFieldToTab("Root.SingleSignOn", new FieldGroup("Encrypt NameID", new CheckboxField("IdPnameIdEncrypted", "Indicates that the nameID of the <samlp:logoutRequest> sent by this SP will be encrypted.")));

			$fields->addFieldToTab("Root.SingleSignOn", new FieldGroup("Sign AuthnRequest", new CheckboxField("authnRequestsSigned", "Indicates whether the <samlp:AuthnRequest> messages sent by this SP will be signed.")));

			$fields->addFieldToTab("Root.SingleSignOn", new FieldGroup("Sign Logout Request", new CheckboxField("logoutRequestSigned", "Indicates whether the <samlp:logoutRequest> messages sent by this SP will be signed.")));

			$fields->addFieldToTab("Root.SingleSignOn", new FieldGroup("Sign Logout Response", new CheckboxField("logoutResponseSigned", "Indicates whether the <samlp:logoutResponse> messages sent by this SP will be signed.")));

			$fields->addFieldToTab("Root.SingleSignOn", new FieldGroup("Sign Metadata", new CheckboxField("signMetadata", "It will use cert files keyFileName => metadata.key, certFileName => metadata.crt")));

			$fields->addFieldToTab("Root.SingleSignOn", new FieldGroup("Require Signed Messages", new CheckboxField("wantMessagesSigned", "Indicates a requirement for the <samlp:Response>, <samlp:LogoutRequest> and <samlp:LogoutResponse> elements received by this SP to be signed.")));

			$fields->addFieldToTab("Root.SingleSignOn", new FieldGroup("Require Signed Assertions", new CheckboxField("wantAssertionsSigned", "Indicates a requirement for the <saml:Assertion> elements received by this SP to be signed.")));

			$fields->addFieldToTab("Root.SingleSignOn", new FieldGroup("Require NameID Encrypted", new CheckboxField("wantNameIdEncrypted", "Indicates a requirement for the NameID received by this SP to be encrypted.")));

			$fields->addFieldToTab("Root.SingleSignOn", new FieldGroup("Authentication Context", new CheckboxField("requestedAuthnContext", "Set to false and no AuthContext will be sent in the AuthNRequest, Set true or don't present thi parameter and you will get an AuthContext 'exact' 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport'")));

			$fields->addFieldToTab("Root.SingleSignOn", new FieldGroup("Contact Details", new TextField("ContactPersonTechnicalName", "Technical Contact Name"), new TextField("ContactPersonTechnicalEmail", "Technical Contact Email"), new TextField("ContactPersonSupportName", "Support Contact Name"), new TextField("ContactPersonSupportEmail", "Support Contact Email")));

			$fields->addFieldToTab(
				"Root.SingleSignOn",
				new FieldGroup("Organisation Details",
					new TextField("OrganisationName", "Origanisation Name"),
					new TextField("OrganisationDisplayName", "Organisation Display Name"),
					new TextField("OrganisationUrl", "Organisation URL")
				)
			);
		}
	}
}