<?php
/**
 * An Identity Provider represents a collection identity providers for authentication purposes.
 * 
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
	private static $db = array(
		"Title" => "Varchar(512)",
		"Active" => "Boolean",
		"entityid" => "Varchar(512)",
		"singleSignOnServiceUrl" => "Varchar(512)",
		"singleSignOnServiceBinding" => "Varchar(512)",
		"NameIDFormat" => "Varchar(512)",
		"x509cert" => "Text",
		"privateKey" => "Text",

	);
	
	private static $has_many = array(
	);
	
	private static $belongs_many_many = array(		
	);
	
	private static $default_sort = '"Title"';
	
	private static $singular_name = 'Identity Provder';

	private static $plural_name = 'Identity Providers';
	
	public function getCMSFields() {
		$fields = parent::getCMSFields();
		
		// $fields->addFieldToTab(
		// 	'Root.Main', 
		// 	$permissionField = new PermissionCheckboxSetField(
		// 		'Codes',
		// 		singleton('Permission')->i18n_plural_name(),
		// 		'PermissionRoleCode',
		// 		'RoleID'
		// 	)
		// );
		// $permissionField->setHiddenPermissions(
		// 	Config::inst()->get('Permission', 'hidden_permissions')
		// );
		
		return $fields;
	}
	
	public function onAfterDelete() {
		parent::onAfterDelete();

		// TODO if there are any other Identity Providers make the first one active
		
	}

	public function canView($member = null) {
		return Permission::check('ADMIN');
	}

	public function canCreate($member = null) {
		return Permission::check('ADMIN');
	}

	public function canEdit($member = null) {
		return Permission::check('ADMIN');
	}

	public function canDelete($member = null) {
		return Permission::check('ADMIN');
	}
}
