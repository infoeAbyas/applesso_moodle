<?php
// This file is part of Moodle - http://moodle.org/
//
// Moodle is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Moodle is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Moodle.  If not, see <http://www.gnu.org/licenses/>.

namespace core\oauth2\service;

use core\oauth2\issuer;
use core\oauth2\endpoint;
use core\oauth2\user_field_mapping;
use core\oauth2\discovery\openidconnect;

/**
 * Class for Apple oAuth service, with the specific methods related to it.
 *
 * @package    core
 * @copyright  2022 eabyas
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class apple extends openidconnect implements issuer_interface {

    /**
     * Build an OAuth2 issuer, with all the default values for this service.
     *
     * @return issuer The issuer initialised with proper default values.
     */
    public static function init(): issuer {
        $record = (object) [
            'name' => 'Apple',
            'image' => 'https://www.apple.com/apple-touch-icon.png',
            'baseurl' => '',
            'loginscopes' => 'public_profile email',
            'loginscopesoffline' => 'public_profile email',
            'showonloginpage' => issuer::EVERYWHERE,
            'servicetype' => 'apple',
        ];

        $issuer = new issuer(0, $record);
        return $issuer;
    }

    /**
     * Create endpoints for this issuer.
     *
     * @param issuer $issuer Issuer the endpoints should be created for.
     * @return issuer
     */
    public static function create_endpoints(issuer $issuer): issuer {
        // The Apple API version.
        $apiversion = '1.0';
        // User information fields that we want to fetch.
        $infofields = [
            'id',
            'first_name',
            'last_name',
            'picture.type(large)',
            'name',
            'email',
        ];
        $endpoints = [
            'authorization_endpoint' => sprintf('https://appleid.apple.com/auth/authorize', $apiversion),
            'token_endpoint' => 'https://appleid.apple.com/auth/token',
            'userinfo_endpoint' => '',
        ];

        foreach ($endpoints as $name => $url) {
            $record = (object) [
                'issuerid' => $issuer->get('id'),
                'name' => $name,
                'url' => $url
            ];
            $endpoint = new endpoint(0, $record);
            $endpoint->create();
        }

        // Create the field mappings.
        $mapping = [
            'name' => 'alternatename',
            'last_name' => 'lastname',
            'email' => 'email',
            'first_name' => 'firstname',
            'picture-data-url' => 'picture',
        ];
        foreach ($mapping as $external => $internal) {
            $record = (object) [
                'issuerid' => $issuer->get('id'),
                'externalfield' => $external,
                'internalfield' => $internal
            ];
            $userfieldmapping = new user_field_mapping(0, $record);
            $userfieldmapping->create();
        }

        return $issuer;
    }
}
