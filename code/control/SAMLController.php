<?php
/**
 * This controller handles serving metadata requests for the IdP, as well as handling creating new users and logging
 * them into SilverStripe after being authenticated at the IdP. You can also change how members are looked up in the
 * database from after successful SAML authorization. To do so, extend this class and customize your YAML config:
 *
 * your-saml-config.yml:
 *
    Injector:
      SAMLController: YourSAMLController
 *
 * Then override ->getMemberFromAuth() and use exceptions to pass errors messages back to the form, if necessary.
 *
 * @author  Sean Harvey, sean@silverstripe.com
 * @author	Patrick Nelson, pat@catchyour.com
 */
class SAMLController extends Controller
{
    /**
     * @var array
     */
    private static $allowed_actions = [
        'index',
        'login',
        'logout',
        'acs',
        'sls',
        'metadata'
    ];

    /**
     * Assertion Consumer Service
     *
     * The user gets sent back here after authenticating with the IdP, off-site.
     * The earlier redirection to the IdP can be found in the SAMLAuthenticator::authenticate.
     *
     * After this handler completes, we end up with a rudimentary Member record (which will be created on-the-fly
     * if not existent), with the user already logged in. Login triggers memberLoggedIn hooks, which allows
     * LDAP side of this module to finish off loading Member data.
     *
     * @throws OneLogin_Saml2_Error
     */
    public function acs()
    {
        /** @var OneLogin_Saml2_Auth $auth */
        $auth = Injector::inst()->get('SAMLHelper')->getSAMLAuth();

        // TODO: Required to workaround a *possible* bug/regression caused by php-saml package: https://github.com/onelogin/php-saml/pull/175#issuecomment-323235699
        $auth->getSettings()->setBaseURL('');

        $auth->processResponse();

        $error = $auth->getLastErrorReason();
        if (!empty($error)) {
            SS_Log::log($error, SS_Log::ERR);
            Form::messageForForm("SAMLLoginForm_LoginForm", "Authentication error: '{$error}'", 'bad');
            Session::save();
            return $this->getRedirect();
        }

        if (!$auth->isAuthenticated()) {
            Form::messageForForm("SAMLLoginForm_LoginForm", _t('Member.ERRORWRONGCRED'), 'bad');
            Session::save();
            return $this->getRedirect();
        }

        // Fetch member based on information in authorization response.
        try {
            $member = $this->getMemberFromAuth($auth);

        } catch(Exception $e) {
            // Log and pass exception message back to form and
            SS_Log::log('Error in ->getMemberFromAuth(): ' . $e->getMessage(), SS_Log::ERR);
            Form::messageForForm("SAMLLoginForm_LoginForm", $e->getMessage(), 'bad');
            Session::save();
            return $this->getRedirect();
        }

        // Fetch attributes passed from SSO/SAML server and apply them to our Member object, if possible.
        $attributes = $auth->getAttributes();
        SS_Log::log('Fetched attributes: ' . print_r($attributes, true), SS_Log::DEBUG);
        foreach ($member->config()->claims_field_mappings as $claim => $field) {
            if (!isset($attributes[$claim][0])) {
                SS_Log::log(
                    sprintf(
                        'Claim rule \'%s\' configured in LDAPMember.claims_field_mappings, but wasn\'t passed through. Please check IdP claim rules.',
                        $claim
                    ), SS_Log::WARN
                );

                continue;
            }

            $member->$field = $attributes[$claim][0];
        }

        $member->SAMLSessionIndex = $auth->getSessionIndex();

        // This will trigger LDAP update through LDAPMemberExtension::memberLoggedIn.
        // The LDAP update will also write the Member record. We shouldn't write before
        // calling this, as any onAfterWrite hooks that attempt to update LDAP won't
        // have the Username field available yet for new Member records, and fail.
        // Both SAML and LDAP identify Members by the GUID field.
        $member->logIn();

        return $this->getRedirect();
    }

    /**
     * Generate this SP's metadata. This is needed for intialising the SP-IdP relationship.
     * IdP is instructed to call us back here to establish the relationship. IdP may also be configured
     * to hit this endpoint periodically during normal operation, to check the SP availability.
     */
    public function metadata()
    {
        try {
            $auth = Injector::inst()->get('SAMLHelper')->getSAMLAuth();
            $settings = $auth->getSettings();
            $metadata = $settings->getSPMetadata();
            $errors = $settings->validateMetadata($metadata);
            if (empty($errors)) {
                header('Content-Type: text/xml');
                echo $metadata;
            } else {
                throw new \OneLogin_Saml2_Error(
                    'Invalid SP metadata: ' . implode(', ', $errors),
                    \OneLogin_Saml2_Error::METADATA_SP_INVALID
                );
            }
        } catch (Exception $e) {
            SS_Log::log($e->getMessage(), SS_Log::ERR);
            echo $e->getMessage();
        }
    }

    /**
     * @return SS_HTTPResponse
     */
    protected function getRedirect()
    {
        // Absolute redirection URLs may cause spoofing
        if (Session::get('BackURL') && Director::is_site_url(Session::get('BackURL'))) {
            return $this->redirect(Session::get('BackURL'));
        }

        // Spoofing attack, redirect to homepage instead of spoofing url
        if (Session::get('BackURL') && !Director::is_site_url(Session::get('BackURL'))) {
            return $this->redirect(Director::absoluteBaseURL());
        }

        // If a default login dest has been set, redirect to that.
        if (Security::config()->default_login_dest) {
            return $this->redirect(Director::absoluteBaseURL() . Security::config()->default_login_dest);
        }

        // fallback to redirect back to home page
        return $this->redirect(Director::absoluteBaseURL());
    }

    /**
     * Return a member (or create a new one) based on the information provided by successful authorization response.
     *
     * @param OneLogin_Saml2_Auth $auth
     * @throws Exception
     * @return Member
     */
    protected function getMemberFromAuth(OneLogin_Saml2_Auth $auth)
    {
        // TODO: This is assuming the name ID is a base64 encoded binary string that isn't transient (see last TODO below).
        $decodedNameId = base64_decode($auth->getNameId());
        // check that the NameID is a binary string (which signals that it is a guid
        if (ctype_print($decodedNameId)) {
            throw new Exception("Name ID provided by IdP is not a binary GUID. ");
        }

        // transform the NameId to guid
        // TODO: This validation is redundant as it is already being generated from a method controlled in this code.
        $guid = SAMLUtil::bin_to_str_guid($decodedNameId);
        if (!SAMLUtil::validGuid($guid)) {
            throw new Exception("Not a valid GUID '{$guid}' recieved from server.");
        }

        // Write a rudimentary member with basic fields on every login, so that we at least have something
        // if LDAP synchronisation fails.
        // TODO: This is pointless at the moment since it is derived from a transient (and thus temporary) value, therefore
        // TODO: this effectively would effectively recreate an empty member object on every single login.
        /** @var Member $member */
        $member = Member::get()->filter('GUID', $guid)->limit(1)->first();
        if (!($member && $member->exists())) {
            $member = new Member();
            $member->GUID = $guid;
        }

        return $member;
    }
}
