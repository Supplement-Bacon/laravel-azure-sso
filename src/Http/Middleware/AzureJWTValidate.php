<?php

namespace SupplementBacon\AzureSSO\Http\Middleware;

use Closure;
use Exception;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Storage;
use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Math\BigInteger;
use Symfony\Component\HttpFoundation\Response;

/**
 * List of available claims is available on Microsoft website
 * @see https://learn.microsoft.com/en-us/azure/active-directory/develop/id-tokens
 */
class AzureJWTValidate
{
    private const PUBLIC_KEY_CACHE_PATH = 'azure-cache/public-key';

    /** @var array Open ID Connect metadata document */
    protected $openIdConfiguration;

    /** @var string The tenant ID */
    public $tenant;

    /** @var string Default Open ID Connect version */
    public $defaultEndPointVersion = '2.0';

    /** @var string Azure AD B2C App Client ID */
    protected $clientId;

    /** @var ?PublicKey $publicKey Public key containing the kid, modulus, exponent etc. */
    private $publicKey;

    /** @var int Leeway given for JWT to correct possible errors in having Azure tokens not match server time */
    public static $leeway = 0;

    public function __construct()
    {
        $this->clientId = config('azure-sso.client_id');
        $this->tenant = config('azure-sso.tenant_id');
        $this->publicKey = null;
    }

    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure(\Illuminate\Http\Request): (\Illuminate\Http\Response|\Illuminate\Http\RedirectResponse)  $next
     * @return \Illuminate\Http\Response|\Illuminate\Http\RedirectResponse
     */
    public function handle(Request $request, Closure $next)
    {
        $authorizationHeader = $request->header('Authorization');
        $accessToken = \trim((string) \preg_replace('/^\s*Bearer\s/', '', $authorizationHeader));

        if (!$accessToken) {
            return response()->json()->setStatusCode(Response::HTTP_UNAUTHORIZED);
        }

        $cachedKey = null;

        if (Storage::disk('local')->exists(self::PUBLIC_KEY_CACHE_PATH)) {

            $cachedKey = Storage::disk('local')->get(self::PUBLIC_KEY_CACHE_PATH);

            if ($cachedKey) {
                $cachedKey = new PublicKey(json_decode($cachedKey, true));
            }
        }

        $kid = $this->getAccessTokenKid($accessToken);

        try {
            $claims = $this->validateToken($accessToken, $kid === $cachedKey?->kid ? $cachedKey : null);
        } catch (ExpiredException $e) {
            return response()->json()->setStatusCode(Response::HTTP_UNAUTHORIZED);
        }

        $request->request->add(['oid' => $claims['oid']]);

        return $next($request);
    }

    /**
     * Validates provided access token
     *
     * @param string $accessToken Json Web Token
     * @return array Access token claims ie. aud, iss, exp etc.
     * @throws MissingResponseException|Exception
     */
    private function validateToken(string $accessToken, ?PublicKey $keyData = null)
    {
        $headerPayload = $this->getAccessTokenHeader($accessToken);

        if (!$keyData) {
            # Fetch the public key based on token header kid (key ID) value
            $keyData = $this->getJwtVerificationKey($headerPayload->kid);

            if (!$keyData) {
                throw new Exception("No key found. Invalid kid provided.");
            }

            // Cache the newly fetched key
            Storage::disk('local')->put(self::PUBLIC_KEY_CACHE_PATH, json_encode((array) $keyData));
        }

        $publicKey = $this->generatePublicKeyFromModulusAndExponent($keyData->n, $keyData->e);

        # Set a bit of leeway
        if (self::$leeway !== 0) {
            JWT::$leeway = self::$leeway;
        }

        $claims = (array) JWT::decode($accessToken, new Key($publicKey, $headerPayload->alg));
        $this->validateTokenClaims($claims);

        return $claims;
    }

    /**
     * Get access token header payload
     *
     * @param string $accessToken
     * @return object
     */
    private function getAccessTokenHeader(string $accessToken): object
    {
        list($header) = explode('.', $accessToken);
        return json_decode(base64_decode($header));
    }

    /**
     * Returns the public key data for provided key ID
     *
     * @param string $kid
     * @return PublicKey|null
     * @throws MissingResponseException
     */
    private function getJwtVerificationKey(string $kid): ?PublicKey
    {
        $keys = [];

        $discoveredKeys = $this->request($this->getDiscoveryUrl());

        if (isset($discoveredKeys->keys) && ($discoveredKeys->keys)) {
            foreach ($discoveredKeys->keys as $key) {
                $keys[$key->kid] = $key;
            }
        }

        if (isset($keys[$kid])) {
            $this->publicKey = new PublicKey((array) $keys[$kid]);
        }

        return $this->publicKey;
    }

    /**
     * Validate token claims against tenant information
     *
     * @param array $tokenClaims
     * @throws InvalidClaimException
     * @throws MissingResponseException
     */
    private function validateTokenClaims(array $tokenClaims)
    {
        if ($this->clientId !== $tokenClaims['aud']) {
            throw new Exception('The client_id or audience is invalid');
        }

        $tenant = $this->getTenantDetails($this->tenant);

        if ($tokenClaims['iss'] != $tenant->issuer) {
            throw new Exception('Invalid token issuer (tokenClaims[iss]' . $tokenClaims['iss'] . ', tenant[issuer] ' . $tenant->issuer . ')');
        }
    }

    /**
     * Generate a public key from modulus (n) and exponent (e)
     *
     * @param string $modulus
     * @param string $exponent
     *
     * @return string
     */
    private function generatePublicKeyFromModulusAndExponent(string $modulus, string $exponent): string
    {
        return PublicKeyLoader::load([
            'n' => new BigInteger($this->base64UrlDecode($modulus), 256),
            'e' => new BigInteger($this->base64UrlDecode($exponent), 256),
        ]);
    }

    /**
     * Base 64 URL decode specific string while replacing underscore
     *
     * @param string $data
     * @return string
     */
    private function base64UrlDecode(string $data): string
    {
        $base64data = strtr($data, '-_', '+/');
        return base64_decode($base64data);
    }

    /**
     * Return JSON document containing public key information.
     *
     * It is recommended to fetch this dynamically from OpenID Connect metadata endpoint,
     * but we don't want to make another network call.
     *
     * @return string
     */
    private function getDiscoveryUrl(): string
    {
        return "https://login.microsoftonline.com/{$this->tenant}/discovery/v2.0/keys?appid={$this->clientId}";
    }

    /**
     * Return the full Open ID Connect metadata document URL
     *
     * @param string $version
     * @return string
     */
    private function getOpenIdConfigurationUrl(string $version): string
    {
        return "https://login.microsoftonline.com/{$this->tenant}/v{$version}/.well-known/openid-configuration";
    }

    /**
     * Return tenant details
     *
     * @param string $tenant
     * @return mixed
     * @throws MissingResponseException
     */
    private function getTenantDetails(string $tenant)
    {
        return $this->getOpenIdConfiguration($tenant, $this->defaultEndPointVersion);
    }

    /**
     * Return Open ID Connect metadata
     *
     * @param string $tenant
     * @param string $version
     * @return mixed
     *
     * @throws MissingResponseException
     */
    protected function getOpenIdConfiguration(string $tenant, string $version)
    {
        if (!isset($this->openIdConfiguration) || !is_array($this->openIdConfiguration)) {
            $this->openIdConfiguration = [];
        }

        if (!array_key_exists($tenant, $this->openIdConfiguration)) {
            $this->openIdConfiguration[$tenant] = [];
        }

        if (!array_key_exists($version, $this->openIdConfiguration[$tenant])) {
            $openIdConfigurationUri = $this->getOpenIdConfigurationUrl($version);
            $response = $this->request($openIdConfigurationUri);

            $this->openIdConfiguration[$tenant][$version] = $response;
        }

        return $this->openIdConfiguration[$tenant][$version];
    }

    /**
     * Read file from URL into a string
     *
     * @param string $url
     * @return mixed
     * @throws MissingResponseException
     */
    private function request(string $url)
    {
        $data = file_get_contents($url);

        if (!$data) {
            throw new Exception("No response from $url");
        }

        return json_decode($data);
    }

    /**
     * Return the key ID used to sign this access token
     *
     * @param string $accessToken
     * @return string|null
     */
    public function getAccessTokenKid(string $accessToken): ?string
    {
        $headers = $this->getAccessTokenHeader($accessToken);
        return $headers->kid ?? null;
    }
}

class PublicKey
{
    public $kid;
    public $use;
    public $kty;
    public $x5c;
    public $e;
    public $n;

    public function __construct(array $args)
    {
        $this->validateArgs($args);

        foreach ($args as $k => $v) {
            $this->{$k} = $v;
        }
    }

    private function validateArgs(array $args)
    {
        $vars = get_class_vars(__CLASS__);

        foreach ($vars as $k => $v) {
            if (!isset($args[$k])) {
                throw new \InvalidArgumentException("Missing property $k in arguments");
            }
        }
    }
}
