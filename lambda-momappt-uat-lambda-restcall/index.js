const axios = require('axios');
const xml2js = require('xml2js');
const AWS = require('aws-sdk');
const https = require('https');
const querystring = require('querystring');

// Initialize AWS clients
const secretsManager = new AWS.SecretsManager();
const s3 = new AWS.S3();

// Secret names
const SECRET_NAME = 'rest/credentials/crm';
const apiBaseUrl = process.env.API_BASE_URL;

// Utility: Filter out noisy headers
function sanitizeHeaders(originalHeaders) {
    const noisyHeaderKeys = [
        'host', 'via', 'x-amz-cf-id', 'x-amzn-cipher-suite', 'x-amzn-tls-version',
        'x-amzn-trace-id', 'x-amzn-vpc-id', 'x-amzn-vpce-id', 'x-amzn-vpce-config',
        'x-forwarded-for', 'x-forwarded-port', 'x-forwarded-proto', 'x-apigw-api-id',
        'postman-token', 'x-envoy-expected-rq-timeout-ms', 'x-origin-verify',
        'x-request-id', 'x-upstream-domain'
    ];
    const cleanedHeaders = {};
    for (const [key, value] of Object.entries(originalHeaders || {})) {
        if (!noisyHeaderKeys.includes(key.toLowerCase())) {
            cleanedHeaders[key] = value;
        }
    }
    return cleanedHeaders;
}

// Fetch credentials from Secrets Manager
async function getCredentials(secretName) {
    console.log("Fetching secret:", secretName);
    const secret = await secretsManager.getSecretValue({ SecretId: secretName }).promise();
    return JSON.parse(secret.SecretString);
}

exports.handler = async (event) => {
    try {
        console.log("Incoming event:", JSON.stringify(event, null, 2));

        const proxyPath = event.path || "";
        if (!proxyPath) throw new Error("Missing request path");

        if (!apiBaseUrl) throw new Error(`Missing required API_BASE_URL`);

        const lowerPath = proxyPath.toLowerCase();
        const apiV1Index = lowerPath.indexOf('/api/v1/');
        if (apiV1Index === -1) throw new Error("Path must contain '/api/v1/'");

        let forwardedPath = proxyPath.substring(apiV1Index);
        let prefix = "", urlPrefix = "";

        if (lowerPath.includes("isps")) {
            prefix = "ISPS";
            urlPrefix = "iSPS";
        } else if (lowerPath.includes("spcs")) {
            prefix = "SPCS";
            urlPrefix = "spcs";
        } else if (lowerPath.includes("crm")) {
            prefix = "CRM";
            urlPrefix = "crm";
            forwardedPath = forwardedPath.replace(/api\/v1/, 'apiv1/crm');
            console.log("crmPath:", forwardedPath);
        }

        // ✅ Remove any leading slashes from forwardedPath to avoid //
        const sanitizedForwardedPath = forwardedPath.replace(/^\/+/, '');
        const targetUrl = `${apiBaseUrl}/${urlPrefix}/${sanitizedForwardedPath}`;
        console.log("Forwarding to:", targetUrl);

        const getEnv = (key) => prefix ? process.env[`${prefix}_${key}`] : process.env[key];
        const enableJwt = (getEnv("ENABLE_JWT") || "false").toLowerCase() === "true";
        const enableApiKey = (getEnv("ENABLE_API_KEY") || "false").toLowerCase() === "true";

        // Optional JWT generation
        let accessToken = null;
        if (enableJwt) {
            const jwtEndpoint = getEnv("JWT_ENDPOINT");
            const jwtScope = getEnv("JWT_SCOPE");
            const jwtGrantType = getEnv("JWT_GRANT_TYPE") || "client_credentials";
            const jwtAuth = getEnv("JWT_AUTHORIZATION");
            const clientId = getEnv("CLIENT_ID");
            const clientSecret = getEnv("CLIENT_SECRET");

            if (!jwtEndpoint || !jwtScope || !jwtAuth || !clientId) {
                throw new Error(`Missing required JWT environment variables for prefix '${prefix}'`);
            }

            console.log("JWT enabled: requesting token...");
            const postData = querystring.stringify({
                scope: jwtScope,
                grant_type: jwtGrantType,
                client_id: clientId,
                ...(clientSecret && { client_secret: clientSecret })
            });

            const jwtResponse = await axios.post(jwtEndpoint, postData, {
                headers: {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Authorization": jwtAuth
                }
            });

            if (!jwtResponse.data?.access_token) {
                throw new Error("access_token not received from JWT endpoint");
            }

            accessToken = jwtResponse.data.access_token;
            console.log("Access token (truncated):", accessToken.substring(0, 20) + "...");
        }

        // Handle body decoding
        let bodyData = event.body;
        if (event.isBase64Encoded && bodyData) {
            bodyData = Buffer.from(bodyData, 'base64').toString('utf8');
        }

        // Build query string if present
        const queryString = event.queryStringParameters
            ? "?" + new URLSearchParams(event.queryStringParameters).toString()
            : "";

        // Clean and build headers
        let headers = sanitizeHeaders(event.headers);
        if (enableJwt && accessToken) {
            headers["Authorization"] = `Bearer ${accessToken}`;
        }

        if (enableApiKey) {
            const credentials = await getCredentials(SECRET_NAME);
            const apiKey = credentials.apikey;
            if (apiKey) {
                headers["x-api-key"] = apiKey;
                console.log("API key added to headers.");
            } else {
                throw new Error(`API key is enabled but no API key found in secret for prefix '${prefix}'`);
            }
        }

        // Axios request
        const method = event.httpMethod.toLowerCase();
        const axiosConfig = {
            method,
            url: targetUrl + queryString,
            headers,
            data: bodyData,
            validateStatus: () => true
        };

        console.log("Forwarding request with config:", axiosConfig);

        const forwardResponse = await axios(axiosConfig);
        console.log("Response received:", forwardResponse.status);

        return {
            statusCode: forwardResponse.status,
            headers: forwardResponse.headers,
            body: typeof forwardResponse.data === "string"
                ? forwardResponse.data
                : JSON.stringify(forwardResponse.data)
        };

    } catch (error) {
        console.error("Error processing request:", error.message);
        return {
            statusCode: 500,
            body: JSON.stringify({ message: "Error processing request", error: error.message })
        };
    }
};