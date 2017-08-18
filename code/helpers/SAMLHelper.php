<?php
/**
 * This class acts as a simple wrapper for the OneLogin implementation, so that we can configure and inject it via the
 * config system. See SAMLConfiguration and override it to customize how OneLogin_Saml2_Auth is configured.
 */

class SAMLHelper extends Object
{
    /**
     * @var array
     */
    public static $dependencies = [
        'SAMLConfService' => '%$SAMLConfService',
    ];

    /**
     * Configured by Injector. See SAMLConfiguration.php for details on how to customize.
     *
     * @var SAMLConfiguration
     */
    public $SAMLConfService;

    /**
     * @return OneLogin_Saml2_Auth
     */
    public function getSAMLauth()
    {
        $samlConfig = $this->SAMLConfService->asArray();
        return new \OneLogin_Saml2_Auth($samlConfig);
    }
}
