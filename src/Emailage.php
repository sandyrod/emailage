<?php
    namespace Sandyrod\emailage;
    /**
     * Create for Emailage to provide SDK access to their API through PHP
     * @author jpitcher
     *
     */
    class Emailage
    {
        /**
         * The allowed Format Values.
         *
         * This Array is used to Verify that if a format is changed, that the changed value is valid to Emailage.
         * @var ARRAY
         */
            private $allowed_formats = Array('json', 'xml');

        /**
         * The Allowed Signature Methods.
         *
         * This Array is used to Verify that if a Signature Method is changed, that the changed value is valid to Emailage.
         * @var ARRAY
         */
            private $allowed_signature_methods = Array('sha1', 'sha256', 'sha384', 'sha512');

        /**
         * The prefix to the URL.
         * @var STRING
         */
            private $URL_prefix = 'https://';

        /**
         * The String appended to the URL if Sandbox == TRUE
         * @var STRING
         */
            private $URL_sandbox = 'sandbox';

        /**
         * The String appended to the URL if Sandbox == FALSE
         * @var STRING
         */
            private $URL_live = 'api';

        /**
         * The Apex of the domain name, used for building the full URL
         * @var STRING
         */
            private $URL_apex = 'emailage.com/';

        /**
         * The Method Base that we attach to every full URL
         * @var STRING
         */
            private $URL_method_base = 'EmailAgeValidator/';

        /**
         * What we append to the URL if setting_flag == TRUE
         * @var STRING
         */
            private $URL_method_flag = 'flag/';

        /**
         * The Current Setting of Format
         * @var STRING
         */
            private $setting_format = 'json';

        /**
         * The Current Setting for Signature Method
         * @var STRING
         */
            private $setting_signature_method = 'sha1';

        /**
         * The Current Setting for if the SDK should connect to the sandbox or not.
         * @var BOOLEAN
         */
            private $setting_sandbox = TRUE;
        /**
         * The Current Setting for if the Full URL should include the flag component
         * @var BOOLEAN
         */
            private $setting_flag = FALSE;

        /**
         * The Account SID provided to you from Emailage.
         * @var STRING
         */
            private $setting_account_sid;

        /**
         * The Auth Token provided to you from Emailage.
         * @var STRING
         */
            private $setting_auth_token;

        /**
         * The Current Setting for if the SDK should Validate the Response returned from Emailage
         * @var BOOLEAN
         */
            private $setting_validate_response = TRUE;

        /**
         * The Current Setting for if the SDK should return the Emailage Response as a Parsed Object, or just as a String and allow you to deal with parsing the object
         * @var BOOLEAN
         */
            private $setting_return_parsed_result = TRUE;
        /**
         * The Request Type of the API Call.  Currently locked at GET.
         * @var STRING
         */
            private $request_type = 'GET';


        /**
         * The Additional Parameters that the user can provide to the Query Calls
         * @var unknown
         */
            private $allowed_parameters = Array
            (
                'firstname',
                'lastname',
                'billaddress',
                'billcity',
                'billregion',
                'billpostal',
                'billcountry',
                'shipaddress',
                'shipcity',
                'shipregion',
                'shippostal',
                'shipcountry',
                'phone',
                'transamount',
                'transcurrency',
                'user_email',
                'transorigin',
                'existingcustomer',
                'useragent',
                'acceptlang',
                'response_language',
                'urid',
                'customerid',
                'deviceid',
                'devicesource',
                'time_to_service',
                'service_date',
                'secondary_email',
                'service_location',
                'service_detail',
                'service_category',
                'delivery_type',
                'cardFirstSix',
                'hashedCardNumber',
                'custom1',
                'custom2'
            );


        /**
         * Class Constructor, Sets up the Account SID and Auth Token, and any other settings if you provide them.
         *
         * @param STRING $account_sid
         * @param STRING $auth_token
         * @param BOOLEAN $sandbox
         * @param STRING $format
         * @param STRING $signature_method
         * @param BOOLEAN $validate_response
         * @param BOOLEAN $return_parsed_result
         */
            public function __construct($account_sid, $auth_token, $sandbox = TRUE, $format = 'json', $signature_method = 'sha1', $validate_response = TRUE, $return_parsed_result = TRUE)
            {
                $this->changeSetting('account_sid', $account_sid);
                $this->changeSetting('auth_token', $auth_token);
                $this->changeSetting('sandbox', $sandbox);
                $this->changeSetting('format', $format);
                $this->changeSetting('signature_method', $signature_method);
                $this->changeSetting('validate_response', $validate_response);
                $this->changeSetting('return_parsed_result', $return_parsed_result);
            }

        /**
         * Call if you want to Flag an Email as Fraud.
         * @param STRING $email
         * @param INTEGER $fraudID
         * @return mixed
         */
            public function FlagEmailAsFraud($email, $fraudID)
            {
                return $this->executeQuery($email, NULL, 'fraud', $fraudID);
            }

        /**
         * Call if you want to Flag an Email as Good.
         * @param STRING $email
         * @return mixed
         */
            public function FlagEmailAsGood($email)
            {
                return $this->executeQuery($email, NULL, 'good');
            }

        /**
         * Call if you want to Flag an Email as Neutral.
         * @param STRING $email
         * @return mixed
         */
            public function RemoveFlagFromEmail($email)
            {
                return $this->executeQuery($email, NULL, 'neutral');
            }

        /**
         * Validate an Email Address
         * @param STRING $email
         * @param STRING $recordID
         * @return mixed
         */
            public function QueryEmail($email, Array $parameters = Array())
            {
                $acceptedParameters = $this->validateParametersArray($parameters);
                return $this->executeQuery($email, $acceptedParameters);
            }

        /**
         * Validate an IP Address
         * @param STRING $ip
         * @param STRING $recordID
         * @return mixed
         */
            public function QueryIpAddress($ip, Array $parameters = Array())
            {
                $acceptedParameters = $this->validateParametersArray($parameters);
                return $this->executeQuery($ip, $acceptedParameters);
            }

        /**
         * Validates both an Email Address and an IP Address
         * @param STRING $email
         * @param STRING $ip
         * @param string $recordID
         * @return mixed
         */
            public function QueryEmailAndIpAddress($email, $ip, Array $parameters = Array())
            {
                $acceptedParameters = $this->validateParametersArray($parameters);
                return $this->executeQuery($email . '+' . $ip, $acceptedParameters);
            }

        /**
         * Validates all the Parameters the users has provided.
         *
         * If they are not valid Parameters it throws an error.
         * @param unknown $parameters
         */
            private function validateParametersArray($parameters)
            {
                $validParameters = Array();

                foreach($parameters AS $paramName => $param)
                {
                    $paramName = strtolower($paramName);
                    if(in_array($paramName, $this->allowed_parameters))
                    {
                        $validParameters[$paramName] = $param;
                    }
                    else
                    {
                        $this->handleError('9000', "Invalid Paramater Provided: ($paramName)");
                    }
                }
                return $validParameters;
            }

        /**
         * Creates the Parameters Array for Curl to Execute the Query
         * @param string $query
         * @param string $recordID
         * @param string $flag
         * @param string $fraudID
         * @return SimpleXMLElement|unknown
         */
            private function executeQuery($query, $additionalParameters = NULL, $flag = NULL, $fraudID = NULL)
            {
                /**
                 * Do we need to Add or Remove the Flag from the Full URL ??
                 */
                    if(!is_null($flag))
                    {
                        $this->setting_flag = TRUE;
                    }
                    else
                    {
                        $this->setting_flag = FALSE;
                    }

                // Get the Full URL
                $URL = $this->getURL();

                /**
                 * Create an Array of Parameters
                 */
                    $parameters = Array();
                    $parameters['format'] = $this->setting_format;
                    $parameters['oauth_consumer_key'] = $this->setting_account_sid;
                    $parameters['oauth_nonce'] = uniqid();
                    $parameters['oauth_signature_method'] = 'HMAC-' . strtoupper($this->setting_signature_method);
                    $parameters['oauth_timestamp'] = time();
                    $parameters['oauth_version'] = '1.0';
                /**
                 * Lets Generate our Signature based on the Parameters we already have setup.
                 */
                    $parameters['oauth_signature'] = $this->generateSig($parameters, $URL);

                /**
                 * Lets add the rest of our Parameters.
                 *
                 * You might be saying... Those are going to get sent through to Emailage, 
                 * but they will only get parsed through if their value is NOT NULL
                 */
                    $parameters['query'] = $query;
                    $parameters['flag'] = $flag;
                    $parameters['fraudcodeID'] = $fraudID;

                /**
                 * Lets Add in our Additional Parameters
                 */
                    if(!is_null($additionalParameters))
                    {
                        $parameters = array_merge($parameters, $additionalParameters);
                    }

                // Have Curl Execute the Call and Return the Results
                $results = $this->execute($URL, $parameters);

                // Does the SDK need to Validate the Response?  If so, let's do it.
                if($this->setting_validate_response)
                {
                    $this->validateResponse($results);
                }

                // Should we return the Results As Parsed or just as a String?
                if($this->setting_return_parsed_result)
                {
                    return $this->returnParsedResults($results);
                }
                else
                {
                    return $results;
                }
            }

        /**
         * Validates the Response, and if an Error has occured throws the error and error message.
         * @param Exception $response
         */
            private function validateResponse($response)
            {
                $errorNum = NULL;
                $errorMessage = NULL;

                $parsed_results = $this->returnParsedResults($response);

                if($parsed_results->responseStatus->status == 'failed')
                {
                    $errorNum = (int)$parsed_results->responseStatus->errorCode;
                    $errorMessage = (string)$parsed_results->responseStatus->description;
                    $this->handleError($errorNum, $errorMessage);
                }
            }

        /**
         * Parses the Results and Returns the parsed results.
         * @param string $response
         * @return mixed
         */
            private function returnParsedResults($response)
            {
                if(strtolower($this->setting_format) == 'json')
                {
                    $parsed_results = $this->parseJSON($response);
                }
                else
                {
                    $parsed_results = $this->parseXML($response);
                }
                return $parsed_results;
            }

        /**
         * Parse's and returns the results as XML
         * @param string $response
         * @return SimpleXMLElement
         */
            private function parseXML($response)
            {
                return simplexml_load_string($response);
            }

        /**
         * Parse's and returns the results as JSON object
         * @param string $response
         * @return mixed
         */
            private function parseJSON($response)
            {
                $json_result = json_decode($response);

                // Lets check and see if JSON had an issue Decoding...
                $error = json_last_error();

                if($error != JSON_ERROR_NONE) // Looks like they did.  Let's throw an error based on the Error JSON had.
                {
                    switch ($error) {
                        case JSON_ERROR_DEPTH:
                            $errorNum = 8200;
                            $errorMessage = 'JSON Error Occured. - Maximum stack depth exceeded';
                            break;
                        case JSON_ERROR_STATE_MISMATCH:
                            $errorNum = 8201;
                            $errorMessage = 'JSON Error Occured. - Underflow or the modes mismatch';
                            break;
                        case JSON_ERROR_CTRL_CHAR:
                            $errorNum = 8202;
                            $errorMessage = 'JSON Error Occured. - Unexpected control character found';
                            break;
                        case JSON_ERROR_SYNTAX:
                            $errorNum = 8203;
                            $errorMessage = 'JSON Error Occured. - Syntax error, malformed JSON';
                            break;
                        case JSON_ERROR_UTF8:
                            $errorNum = 8204;
                            $errorMessage = 'JSON Error Occured. - Malformed UTF-8 characters, possibly incorrectly encoded';
                            break;
                        default:
                            $errorNum = 8205;
                            $errorMessage = 'JSON Error Occured. - Unknown error';
                            break;
                    }
                    $this->handleError($errorNum, $errorMessage);
                }
                return $json_result;
            }

        /**
         * Executes the CURL call and returns the results.
         * @param string $URL
         * @param array $parameters
         * @return mixed
         */
            private function execute($URL, $parameters)
            {
                // Attach our Query Parameters to the URL
                $URL .= '?' . http_build_query($parameters);

                $CH = curl_init($URL); // Initialize Curl

                curl_setopt($CH, CURLOPT_RETURNTRANSFER, 1); // Force Curl to return the response

                $results = curl_exec($CH); // Do the Curl Call

                /**
                 * Lets make sure we had no Curl Error's, if we do, let's throw an exception.
                 */
                    if($errno = curl_errno($CH)) {
                        $error_message = curl_strerror($errno);
                        $this->handleError($errno, $error_message);
                    }
                return str_replace("\xEF\xBB\xBF", '', $results); //String Replace is clearing up some characters being sent from Emailage that json_decode doesn't like.
            }

        /**
         * Creates and returns the Signature for EMAILAGE
         * @param array $parameters
         * @param string $URL
         * @return string
         */
            private function generateSig($parameters, $URL)
            {
                $hash_Params = Array();
                $hash_Params[] = strtoupper($this->request_type); // ATM this is just GET
                $hash_Params[] = urlencode($URL); // THE URL we are going to send the call to minus anything upto and after the ?
                $hash_Params[] = urlencode(http_build_query($parameters)); // The Parameters we need to create the Hash.

                // Make and return the Hash.
                return base64_encode(hash_hmac(strtolower($this->setting_signature_method), join('&', $hash_Params), $this->setting_auth_token . '&', TRUE));
            }

        /**
         * Allow users to Change their Settings
         *
         * Throws errors if errors are found.
         * @param string $name
         * @param value $value
         */
            public function changeSetting($name, $value)
            {
                switch(strtolower($name))
                {
                    case 'account_sid':
                    case 'auth_token':
                        // No Validation Needed ...
                    break;

                    case 'format':
                        if(!in_array($value, $this->allowed_formats))
                        {
                            $this->handleError('8000', "Unable to Change Format.  Format is invalid. ($value)");
                        }
                    break;

                    case 'return_parsed_result':
                        if(!is_bool($value))
                        {
                            $this->handleError('8005', "Unable to Return Parsed Results.  Value was not True or False");
                        }
                    break;

                    case 'sandbox':
                        if(!is_bool($value))
                        {
                            $this->handleError('8001', "Unable to Change Sandbox.  Value was not True or False");
                        }
                    break;

                    case 'signature_method':
                        if(!in_array(strtolower($value), $this->allowed_signature_methods))
                        {
                            $this->handleError('8003', "Unable to Change Signature Method.  Signature Method is invalid. ($value)");
                        }
                    break;

                    case 'validate_response':
                        if(!is_bool($value))
                        {
                            $this->handleError('8004', "Unable to Change Validate Response.  Value was not True or False");
                        }
                    break;

                    default:
                        $this->handleError('8100', "Unable to change ($name).  Unknown Setting. ($value)");
                    break;
                }

                $this->saveSetting($name, $value);
            }

        /**
         * Single function for handling errors if we want to change the process in the future.
         * @param int $errorNum
         * @param string $errorMessage
         * @throws Exception
         */
            private function handleError($errorNum, $errorMessage)
            {
                throw new Exception($errorMessage, $errorNum);
            }

        /**
         * Does the Actual Saving of the Setting to the class
         * @param string $name
         * @param string $value
         */
            private function saveSetting($name, $value)
            {
                $settingName = 'setting_' . $name;
                $this->$settingName = $value;
            }

        /**
         * Creates the the URL that we will send the call to.
         * @return string
         */
            private function getURL()
            {
                $URL = $this->URL_prefix;

                // Are we going to the sandbox or the live site?
                if($this->setting_sandbox)
                {
                    $URL .= $this->URL_sandbox;
                }
                else
                {
                    $URL .= $this->URL_live;
                }

                // Lets add on the Apex and the method base
                $URL .= '.' . $this->URL_apex . $this->URL_method_base;

                // Do we need to append the flag method to the url?
                if($this->setting_flag)
                {
                    $URL .= $this->URL_method_flag;
                }

                return $URL;
            }
    }

