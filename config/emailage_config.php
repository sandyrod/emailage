<?php

use sandyrod\emailage\EmailageServiceProvider;

return [

    /*
    |--------------------------------------------------------------------------
    | AWS SDK Configuration
    |--------------------------------------------------------------------------
    |
    | The configuration options set in this file will be passed directly to the
    | `Aws\Sdk` object, from which all client objects are created. This file
    | is published to the application config directory for modification by the
    | user. The full set of possible options are documented at:
    | http://docs.aws.amazon.com/aws-sdk-php/v3/guide/guide/configuration.html
    |
    */
   'EmailageSetting' =>[
        'sandbox' => env('EmailEsandbox',''),
        'signature_method' => env('EmailEsignature_method',''),
        'validate_response' => env('EmailEvalidate_response',''),
        'return_parsed_result' => env('EmailEreturn_parsed_result',''),
   ],
];

