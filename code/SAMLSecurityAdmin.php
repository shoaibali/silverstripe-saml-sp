<?php
/**
 * Security section of the CMS
 *
 * @package framework
 * @subpackage admin
 */
class SAMLSecurityAdmin extends LeftAndMain implements PermissionProvider {
	private static $url_segment = 'saml-security';

	private static $url_rule = '/$Action/$ID/$OtherID';

	private static $menu_title = 'SAML';

	private static $menu_icon = '/silverstripe-saml-sp/images/key.png';

	private static $subitem_class = 'Saml';

	/**
	 * @var array
	 */
	private static $allowed_actions = array(
		'EditForm',
		'saml',
	);

	public function init() {
		parent::init();
		Requirements::javascript(FRAMEWORK_ADMIN_DIR . '/javascript/SecurityAdmin.js');
	}

	/**
	 * Shortcut action for setting the correct active tab.
	 */
	public function saml($request) {
		return $this->index($request);
	}

	public function getEditForm($id = null, $fields = null) {
		// @TODO Duplicate record fetching (see parent implementation)
		if(!$id) $id = $this->currentPageID();
		$form = parent::getEditForm($id);

		// @TODO Duplicate record fetching (see parent implementation)
		$record = $this->getRecord($id);

		if($record && !$record->canView()) {
			return Security::permissionFailure($this);
		}

		// Add import capabilities. Limit to admin since the import logic can affect assigned permissions
		if (Permission::check('ADMIN')) {
			$samlField = GridField::create('SAML',
				false,
				IdentityProvider::get(),
				GridFieldConfig_RecordEditor::create()
			);

			$dataColumns = $samlField->getConfig()->getComponentByType('GridFieldDataColumns');
			$dataColumns->setDisplayFields(array(
				'Title' => 'Title',
				'Active' => 'Active',
				'entityid'=> 'Entity ID',
			));

			$fields = new FieldList(
				$root = new TabSet(
					'Root',
					$samlTab = new Tab('SAML', _t('SAMLSecurityAdmin.SAML', 'SAML'),
						$samlField,
						new LiteralField('SAMLCautionText',
							sprintf('<p class="caution-remove"><strong>%s</strong></p>',
								_t(
									'SAMLSecurityAdmin.SAMLCautionText',
									'Caution: Pages that require authentication will be re-directed to Identity Provder'
								)
							)
						)
					)
				),

				// necessary for tree node selection in LeftAndMain.EditForm.js
				new HiddenField('ID', false, 0)
			);
		}

		// Tab nav in CMS is rendered through separate template
		$root->setTemplate('CMSTabSet');


		$actionParam = $this->request->param('Action');
		if($actionParam == 'saml') {
			$groupsTab->addExtraClass('ui-state-active');
		}

		$actions = new FieldList();

		$form = CMSForm::create(
			$this,
			'EditForm',
			$fields,
			$actions
		)->setHTMLID('Form_EditForm');
		$form->setResponseNegotiator($this->getResponseNegotiator());
		$form->addExtraClass('cms-edit-form');
		$form->setTemplate($this->getTemplatesWithSuffix('_EditForm'));

		// Tab nav in CMS is rendered through separate template
		if($form->Fields()->hasTabset()) {
			$form->Fields()->findOrMakeTab('Root')->setTemplate('CMSTabSet');
		}
		$form->addExtraClass('center ss-tabset cms-tabset ' . $this->BaseCSSClasses());
		$form->setAttribute('data-pjax-fragment', 'CurrentForm');

		$this->extend('updateEditForm', $form);

		return $form;
	}
}
