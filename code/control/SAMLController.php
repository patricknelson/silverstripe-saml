<?php
/**
 * This controller handles serving metadata requests for the IdP, as well as handling creating new users and logging
 * them into SilverStripe after being authenticated at the IdP. You can also change how members are looked up in the
 * database from after successful SAML authorization. To do so, extend this class and customize your YAML config:
 *
 * your-saml-config.yml:
 *
    Injector:
      SAMLController:
        class: YourSAMLController
 *
 * Then override ->getMemberFromAuth() and use exceptions to pass errors messages back to the form, if necessary.
 *
 * @author  Sean Harvey, sean@silverstripe.com
 * @author	Patrick Nelson, pat@catchyour.com
 */
class SAMLController extends Controller
{
    /**
     * Cache the name of the form that this controller needs to pass error messages to. May vary depending on injected classes.
     *
     * @var string
     */
    protected $formName;

	/**
	 * Retain the SAML authenticator for debugging requests/responses.
	 *
	 * @var OneLogin_Saml2_Auth
	 */
    protected $samlAuth;

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
        $auth = $this->getSamlAuth();

        // TODO: Required to workaround a *possible* bug/regression caused by php-saml package: https://github.com/onelogin/php-saml/pull/175#issuecomment-323235699
        $auth->getSettings()->setBaseURL('');

        $auth->processResponse();

        $error = $auth->getLastErrorReason();
        if (!empty($error)) {
        	$message = "Authentication error: '{$error}'";
            $this->log($error);
            Form::messageForForm($this->getFormName(), $message, 'bad');
            Session::save();
            return $this->getRedirect();
        }

        if (!$auth->isAuthenticated()) {
            Form::messageForForm($this->getFormName(), _t('Member.ERRORWRONGCRED'), 'bad');
            Session::save();
            return $this->getRedirect();
        }

        // Fetch member based on information in authorization response.
        try {
            $member = $this->getMemberFromAuth();

        } catch(Exception $e) {
            // Log and pass exception message back to form and
            $this->log('Error in ->getMemberFromAuth(): ' . $e->getMessage());
            Form::messageForForm($this->getFormName(), $e->getMessage(), 'bad');
            Session::save();
            return $this->getRedirect();
        }

        // Fetch attributes passed from SSO/SAML server and apply them to our Member object, if possible.
        $attributes = $auth->getAttributes();
        $this->log('Fetched attributes: ' . print_r($attributes, true), SS_Log::DEBUG);
        foreach ($member->config()->claims_field_mappings as $claim => $field) {
            if (!isset($attributes[$claim][0])) {
				$this->log(sprintf(
					'Claim rule \'%s\' configured in LDAPMember.claims_field_mappings, but wasn\'t passed through. Please check IdP claim rules.',
					$claim
				), SS_Log::WARN);
                continue;
            }

            $member->$field = $attributes[$claim][0];
        }

        $member->SAMLSessionIndex = $auth->getSessionIndex();

        // Log member in and redirect back to initial desired URL.
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
			$auth = $this->getSamlAuth();
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
            $this->log($e->getMessage());
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
     * @throws Exception
     * @return Member
     */
    protected function getMemberFromAuth()
    {
		$auth = $this->getSamlAuth();

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

    /**
     * Generates the correct name for the form that this controller needs to drop errors into.
     *
     * @return string
     */
    public function getFormName()
    {
        if ($this->formName) return $this->formName;

        // Form instance is controlled by the authenticator, so let's use the injector to instantiate that first before
        // statically calling the ::get_login_form() method so we can ensure we get it off the appropriate instance.
        $authenticator = SAMLAuthenticator::create();
        $form = $authenticator::get_login_form($this);
        return $this->formName = $form->FormName();
    }

	/**
	 * Returns current SAML authorization instance to assist with debugging requests/responses.
	 *
	 * @return OneLogin_Saml2_Auth
	 */
    public function getSamlAuth()
	{
		if (!$this->samlAuth) {
			$this->samlAuth = Injector::inst()->get('SAMLHelper')->getSAMLAuth();
		}
		return $this->samlAuth;
	}

	/**
	 * Central logging. If desired, override this to provide more detailed logging.
	 *
	 * @param	string	$message	Message to log.
	 * @param	int		$level		Log level pulled from SS_Log constants.
	 */
	protected function log($message, $level = SS_Log::ERR)
	{
		SS_Log::log($message, $level);
	}
}
