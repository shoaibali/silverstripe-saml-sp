<?php
/**
 * An Identity Provider represents a collection identity providers for authentication purposes.
 *
 * Only one identity provider can be active at any given time. If the <b>Active</b> property is set to TRUE,
 * then that identity provider configuration will be used for authentication.
 *
 * @package saml-sp
 *
 * @property string Title
 * @property string Active
 * @property string Active
 *
 * @method HasManyList Codes() List of PermissionRoleCode objects
 * @method ManyManyList Groups() List of Group objects
 */
class IdentityProvider extends DataObject {
	/**
	 * @var array
	 */
	private static $db = array(
		"Title" => "Varchar(512)",
		"Active" => "Boolean",
		"entityid" => "Varchar(512)",
		"singleSignOnServiceUrl" => "Varchar(512)",
		"singleSignOnServiceBinding" => "Varchar(512)",
		"singleLogoutServiceUrl" => "Varchar(512)",
		"singleLogoutServiceBinding" => "Varchar(512)",
		"NameIDFormat" => "Varchar(512)",
		"x509cert" => "Text",
		"certFingerprint" => "Text",
	);

	private static $default_sort = '"Title"';

	private static $singular_name = 'Identity Provder';

	private static $plural_name = 'Identity Providers';


	/**
	 * Avoid deleting of active IdPs while Single Sign On is active.
	 *
	 * @TODO refactor once enable is a database flag.
	 */
	public function onBeforeDelete() {
		parent::onBeforeDelete();

		// Dont allow to delete an active IdP while the module is enabled.
		if ($this->Active && Config::inst()->get('SingleSignOnConfig', 'EnableSingleSignOn')) {
			user_error(_t(
				'ERROR_UNABLE_TO_DELETE_WHILE_ACTIVE',
				'You cant delete the only active IdP while using Single Sign On.'
			));
		}
	}
}
