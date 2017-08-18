<?php
/**
 * Provides some potentially reusable functions for SAML.
 * 
 * @author  Sean Harvey, sean@silverstripe.com
 */
class SAMLUtil
{
    /**
     * Checks if the string is a valid guid in the format of A98C5A1E-A742-4808-96FA-6F409E799937
     *
     * TODO: This validation is redundant as it is already being generated from a method controlled in this code (see below).
     * TODO: Also it is potentially unnecessary since we're validating a GUID derived from a transient (and thus temporary) value.
     *
     * @param $guid
     * @return bool
     */
    public static function validGuid($guid)
    {
        if (preg_match('/^[A-Z0-9]{8}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{12}?$/', $guid)) {
            return true;
        }
        return false;
    }

    /**
     * Converts a binary string to a GUID.
     *
     * TODO: Consider removal, since this has tight bindings with code that may not prove to be useful (i.e. SAMLController member lookup on a transient value).
     *
     * @param   string  $bin_guid
     * @return  string
     */
    public static function bin_to_str_guid($bin_guid)
    {
        $hex_guid = bin2hex($bin_guid);
        $hex_guid = substr($hex_guid, 0, 32); // Cap at 128 bits, or 16 bytes * 2 bytes per hex char = 32 chars
        $hex_guid_to_guid_str = '';
        for ($k = 1; $k <= 4; ++$k) {
            $hex_guid_to_guid_str .= substr($hex_guid, 8 - 2 * $k, 2);
        }
        $hex_guid_to_guid_str .= '-';
        for ($k = 1; $k <= 2; ++$k) {
            $hex_guid_to_guid_str .= substr($hex_guid, 12 - 2 * $k, 2);
        }
        $hex_guid_to_guid_str .= '-';
        for ($k = 1; $k <= 2; ++$k) {
            $hex_guid_to_guid_str .= substr($hex_guid, 16 - 2 * $k, 2);
        }
        $hex_guid_to_guid_str .= '-' . substr($hex_guid, 16, 4);
        $hex_guid_to_guid_str .= '-' . substr($hex_guid, 20);

        return strtoupper($hex_guid_to_guid_str);
    }

	// TODO: Not used in SAML code.
    public static function str_to_hex_guid($str_guid, $escape = false)
    {
        $str_guid = str_replace('-', '', $str_guid);

        $octet_str = substr($str_guid, 6, 2);
        $octet_str .= substr($str_guid, 4, 2);
        $octet_str .= substr($str_guid, 2, 2);
        $octet_str .= substr($str_guid, 0, 2);
        $octet_str .= substr($str_guid, 10, 2);
        $octet_str .= substr($str_guid, 8, 2);
        $octet_str .= substr($str_guid, 14, 2);
        $octet_str .= substr($str_guid, 12, 2);
        $octet_str .= substr($str_guid, 16, strlen($str_guid));

        if ($escape) {
            $escaped = '\\';
            for ($i = 0; $i < strlen($octet_str); $i+=2) {
                $escaped .= substr($octet_str, $i, 2);
                if ($i != strlen($octet_str) - 2) {
                    $escaped .= '\\';
                }
            }
            return $escaped;
        }

        return $octet_str;
    }


	// TODO: Not used in SAML code.
    public static function bin_to_str_sid($binsid)
    {
        $hex_sid = bin2hex($binsid);
        $rev = hexdec(substr($hex_sid, 0, 2));
        $subcount = hexdec(substr($hex_sid, 2, 2));
        $auth = hexdec(substr($hex_sid, 4, 12));
        $result = "$rev-$auth";

        for ($x=0;$x < $subcount; $x++) {
            $subauth[$x] = hexdec(self::little_endian(substr($hex_sid, 16 + ($x * 8), 8)));
            $result .= "-" . $subauth[$x];
        }

        // Cheat by tacking on the S-
        return 'S-' . $result;
    }

	// TODO: Not used in SAML code.
    // Converts a little-endian hex-number to one, that 'hexdec' can convert
    public static function little_endian($hex)
    {
        $result = '';
        for ($x = strlen($hex) - 2; $x >= 0; $x = $x - 2) {
            $result .= substr($hex, $x, 2);
        }
        return $result;
    }
}
