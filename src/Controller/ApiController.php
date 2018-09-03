<?php
namespace App\Controller;

use Symfony\Component\HttpFoundation\JsonResponse;

class ApiController
{
    /**
     * Returns a 422 Unprocessable Entity
     *
     * @param string $message
     *
     * @return Symfony\Component\HttpFoundation\JsonResponse
     */
    public function respondValidationError($message = 'Validation errors')
    {
        return $this->setStatusCode(422)->respondWithErrors($message);
    }

    /**
     * Returns a 404 Not Found
     *
     * @param string $message
     *
     * @return Symfony\Component\HttpFoundation\JsonResponse
     */
    public function respondNotFound($message = 'Not found!')
    {
        return $this->setStatusCode(404)->respondWithErrors($message);
    }

    /**
     * Returns a 201 Created
     *
     * @param array $data
     *
     * @return Symfony\Component\HttpFoundation\JsonResponse
     */
    public function respondCreated($data = [])
    {
        return $this->setStatusCode(201)->respond($data);
    }


    /**
     * Returns a 400 Unauthorized
     *
     * @param array $data
     *
     * @return Symfony\Component\HttpFoundation\JsonResponse
     */
    public function respondUnauthorized($data = [])
    {
        return $this->setStatusCode(400)->respond($data);
    }


    /**
     * Attempt authorization using jwt-verifier
     *
     * @return bool
     */
    public function isAuthorized(): bool
    {
        if (! isset( $_SERVER['HTTP_AUTHORIZATION'])) {
            return false;
        }

        $authType = null;
        $authData = null;

        // Extract the auth type and the data from the Authorization header.
        @list($authType, $authData) = explode(" ", $_SERVER['HTTP_AUTHORIZATION'], 2);

        // If the Authorization Header is not a bearer type, return a 401.
        if ($authType != 'Bearer') {
            return false;
        }

        // Attempt authorization with the provided token
        try {
            // Setup the JWT Verifier
            $jwtVerifier = (new \Okta\JwtVerifier\JwtVerifierBuilder())
                ->setAdaptor(new \Okta\JwtVerifier\Adaptors\SpomkyLabsJose())
                ->setAudience('api://default')
                ->setClientId('{YOUR_CLIENT_ID}')
                ->setIssuer('https://{yourOktaDomain}/oauth2/default')
                ->build();

            // Verify the JWT from the Authorization Header.
            $jwt = $jwtVerifier->verify($authData);
        } catch (\Exception $e) {

            // We encountered an error, return a 401.
            return false;
        }

        return true;
    }
}

