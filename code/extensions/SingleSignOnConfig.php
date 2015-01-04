<?php

class SingleSignOnConfig extends DataExtension {     


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
		'Debug' => "Boolean", // TODO This should be true in development environment
		'IdPnameIdEncrypted' => "Boolean",				
		'authnRequestsSigned' => "Boolean",				
		'logoutRequestSigned' => "Boolean",				
		'logoutResponseSigned' => "Boolean",				
		'signMetadata' => "Boolean",	// TODO False || True (use sp certs) || array (keyFileName, certFileName)
		'wantMessagesSigned' => "Boolean",				
		'wantAssertionsSigned' => "Boolean",				
		'wantNameIdEncrypted' => "Boolean",				
		'requestedAuthnContext' => "Boolean(1)", // TODO add array support see php-saml advance settings			
		'ContactPersonTechnicalName' => "Varchar",				
		'ContactPersonTechnicalEmail' => "Varchar",				
		'ContactPersonSupportName' => "Varchar",				
		'ContactPersonSupportEmail' => "Varchar",				
		'OrganisationName' => "Varchar",				
		'OrganisationDisplayName' => "Varchar",				
		'OrganisationUrl' => "Varchar",				
	  );

	// This is NOT supported  - instead had to use requireDefaultRecords
	// public function populateDefaults()
	// {

	// 	$this->SPEntityID = Director::absoluteBaseURL();
	// 	$this->ACSurl = Director::absoluteBaseURL() . 'Security/acs';
	// 	$this->ACSbinding = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST';
	// 	$this->SLSurl = Director::absoluteBaseURL() . 'Security/sls';
	// 	$this->SLSbinding = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect';
	// 	$this->NameIDFormat = 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress';
		
	// 	parent::populateDefaults();
	// }


	public function requireDefaultRecords() {

		$SPEntityID = Director::absoluteBaseURL();
		$ACSurl = Director::absoluteBaseURL() . 'Security/acs';
		$ACSbinding = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST';
		$SLSurl = Director::absoluteBaseURL() . 'Security/sls';
		$SLSbinding = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect';
		$NameIDFormat = 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress';
		$FederationUID = 'Email';
		$AttributeMapID = 'mail';

		$defaults = array('SPEntityID' => $SPEntityID,
						  'ACSurl'  => $ACSurl,
						  'ACSbinding'  => $ACSbinding,
						  'SLSurl' => $SLSurl,
						  'SLSbinding' => $SLSbinding,
						  'NameIDFormat' => $NameIDFormat,
						  'FederationUID' => $FederationUID,
						  'AttributeMapID' => $AttributeMapID
						);

		$ensureHasContent = array_keys($defaults);

		$config = SiteConfig::current_site_config();

		foreach($ensureHasContent as $item) {
			if(!$config->$item) {
				$config->$item = $defaults[$item];
			}
		}

		$config->write();
	}


	public function __construct() {
	    parent::__construct();
	}


	function getCMSFields() {
    	$fields = parent::getCMSFields();
    	return $fields;
	}


    public function updateCMSFields(FieldList $fields) {

	   $fields->addFieldToTab("Root.SingleSignOn", new TextField("SPEntityID", "Entity ID"));
	   $fields->addFieldToTab("Root.SingleSignOn", new TextField("ACSurl", "ACSurl"));
	   $fields->addFieldToTab("Root.SingleSignOn", new TextField("ACSbinding", "ACSbinding"));
	   $fields->addFieldToTab("Root.SingleSignOn", new TextField("SLSurl", "SLSurl"));
	   $fields->addFieldToTab("Root.SingleSignOn", new TextField("SLSbinding", "SLSbinding"));
	   $fields->addFieldToTab("Root.SingleSignOn", new TextField("NameIDFormat", "NameIDFormat"));

	   $fields->addFieldToTab("Root.SingleSignOn", new FieldGroup("Federation", new TextField("FederationUID", "SilverStripe Member column"),  new TextField("AttributeMapID", "Attribute from IdP Mapped to SilverStripe Member")));	   
	   //$fields->addFieldToTab("Root.SingleSignOn",);

	   $fields->addFieldToTab("Root.SingleSignOn", new TextAreaField("x509cert", "x509cert"));
	   $fields->addFieldToTab("Root.SingleSignOn", new TextAreaField("privatekey", "privatekey"));

	   $fields->addFieldToTab("Root.SingleSignOn", new FieldGroup("SP Metadata", new LiteralField("Metadata URL", "<a href='" . Director::absoluteBaseURL() . "Security/metadata" ."' target='_blank'>" .  Director::absoluteBaseURL() . "Security/metadata" . "</a>")));

	   $fields->addFieldToTab("Root.SingleSignOn", new FieldGroup("SSO Enabled", new LiteralField("Sigle Sign On Enabled", (Config::inst()->get('SingleSignOnConfig', 'EnableSingleSignOn'))? "Yes" : "No - Please check _config.yml for EnableSingleSignOn: true" )));

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

	   $fields->addFieldToTab("Root.SingleSignOn", new FieldGroup("Organisation Details", 
	   		new TextField("OrganisationName", "Origanisation Name"), 
	   		new TextField("OrganisationDisplayName", "Organisation Display Name"), 
	   		new TextField("OrganisationUrl", "Organisation URL")));

    }



}