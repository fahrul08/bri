<?php

namespace Fwalid08\BRI;

use GuzzleHttp\Client;

class BriApi
{
    private $consumerKey;
    private $consumerSecret;
    private $client;
    private $baseUri = [
        'sandbox' => 'https://sandbox.partner.api.bri.co.id',
        'production' => 'https://partner.api.bri.co.id',
    ];
    private $token;
    private $requestTime;

    public function __construct($credentials)
    {
        $this->consumerKey = $credentials['consumerKey'];
        $this->consumerSecret = $credentials['consumerSecret'];
        $this->client = new Client([
            'base_uri' => $this->baseUri[isset($credentials['sandbox']) && $credentials['sandbox'] ? 'sandbox' : 'production']
        ]);
        $this->token = $this->token();
    }

    public function token()
    {

        if(session_id() === '') {
            session_start();
        }

        if (isset($_SESSION['bri_api_token'])) {
            $tokenData = $_SESSION['bri_api_token'];
            $currentTime = strtotime('-1 hours') * 1000;
            $expiredAt = $tokenData->issued_at + $tokenData->expires_in;
            if ($currentTime < $expiredAt) {
                return $tokenData;
            }

        }

        $response = $this->client->request('POST', '/oauth/client_credential/accesstoken?grant_type=client_credentials', [
            'headers' => [
                'Content-Type' => 'application/x-www-form-urlencoded',
            ],
            'form_params' => [
                'client_id' => $this->consumerKey,
                'client_secret' => $this->consumerSecret,
            ],
        ]);

        $tokenData = json_decode($response->getBody()->getContents());

        if (is_object($tokenData) && isset($tokenData->access_token)) {
            $_SESSION['bri_api_token'] = $tokenData;
            return $tokenData;
        }

        throw new Exception("Access token failed to retrieve.");
    }

    public function signature($args)
    {
        $payloads['path'] = $args['path'];
        $payloads['verb'] = $args['verb'];
        $payloads['token'] = 'Bearer ' . $this->token->access_token;
        $payloads['timestamp'] = $this->dateNow();
        $payloads['body'] = $args['body'];

        $queryArray = [];

        foreach ($payloads as $key => $value) {
            $queryArray[] = trim($key) . '=' . trim($value);
        }

        $queryString = implode('&', $queryArray);

        return base64_encode(hash_hmac('sha256', $queryString, $this->consumerSecret, true));
    }

    public function statements($account, $startDate, $endDate)
    {

        $body = json_encode([
            'accountNumber' => $account,
            'startDate' => $startDate,
            'endDate' => $endDate,
        ]);

        $signature = $this->signature([
            'path' => '/v2.0/statement',
            'verb' => 'POST',
            'body' => $body,
        ]);

        $headers = [
            'Authorization' => 'Bearer ' . $this->token->access_token,
            'BRI-Signature' => $signature,
            'BRI-Timestamp' => $this->requestTime,
            'BRI-External-Id' => substr(md5(uniqid(rand(1,6))), 0, 9),
            'Content-Type' => 'application/json',
        ];

        try {
            
            $response = $this->client->post('/v2.0/statement', [
                'headers' => $headers,
                'body' => $body,
                "http_errors" => false,
            ]);
    
            $statementData = json_decode($response->getBody()->getContents());
    
            if (is_object($statementData) && isset($statementData->transactionTime)) {
                return $statementData;
            }
    
            if (is_object($statementData) && isset($statementData->status)) {
                return $statementData->status->desc;
            }

            throw new \Exception("Data mutasi gagal didapatkan");

        } catch (\GuzzleHttp\Exception\ClientException $e) {
            return $e->getMessage();
        }


    }

    private function dateNow()
    {
        $now = \DateTime::createFromFormat('U.u', microtime(true));
        $now->setTimezone(new \DateTimeZone('GMT'));
        $dateTime = $now->format("Y-m-d\TH:i:s.v\Z");
        $this->requestTime = $dateTime;
        return $dateTime;
    }
}