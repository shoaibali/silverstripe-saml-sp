silverstripe-saml-sp
====================

**** THIS IS NOT PRODUCTION READY MODULE ****

SAML Service Provider for SilverStripe
--------------------------------------

This module adds a Service Provider configuration component to SilverStripe. 
It uses PHP-SAML Toolkit (https://github.com/onelogin/php-saml) to talk SAML to Identity Providers. 

Some ideas and components copied from SimpleSAMLphp module for SilverStripe https://github.com/antons-/silverstripe-ssp. 
However, that module requires heavy file based configuration and SimpleSAMLphp setup.

This module does not let your SilverStripe be an Identity Provider. It currently does not do user provisioning.
It may or may not support Artifact binding, this will need to be confirmed by PHP-SAML Toolkit. 

Configuration
-------------

You can install it using composer or just download it and extract it in to a folder called silverstripe-saml-sp.
Run dev/build?flush=all as usual. 
You should now see two settings, one is visible on left hand side tab called SAML. This is where you will need to add an Identity Provider.
The other setting is under Settings tab of SilverStripe and then under Single Sign On. This is where you will need to provide all Service provder settings.

The module is disabled by default in order to avoid lock-outs. You can enable it by opening up config.yml and setting     EnableSingleSignOn: true
Please make sure you run dev/build after changing the setting. 