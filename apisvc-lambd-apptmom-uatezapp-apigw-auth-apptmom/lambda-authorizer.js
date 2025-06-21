import jwt from 'jsonwebtoken';
import jwkToPem from 'jwk-to-pem';
import axios from 'axios';

// 🔹 Fetch Cognito JWKS URLs & Client IDs from environment variables
const JWKS_URL_RDI = process.env.JWKS_URL_RDI;
const JWKS_URL_IWPS = process.env.JWKS_URL_IWPS;
const JWKS_URL_APPTMOM = process.env.JWKS_URL_APPTMOM;
const JWKS_URL_CRM = process.env.JWKS_URL_CRM;

const JWKS_URL_ISPS = process.env.JWKS_URL_ISPS;
const JWKS_URL_SPCS = process.env.JWKS_URL_SPCS;

const COGNITO_USER_POOL_ID = process.env.COGNITO_USER_POOL_ID;
const CLIENT_ID_RDI = process.env.CLIENT_ID_RDI;
const CLIENT_ID_IWPS = process.env.CLIENT_ID_IWPS;
const CLIENT_ID_APPTMOM = process.env.CLIENT_ID_APPTMOM;
const CLIENT_ID_CRM = process.env.CLIENT_ID_CRM;

const CLIENT_ID_ISPS = process.env.CLIENT_ID_ISPS;
const CLIENT_ID_SPCS = process.env.CLIENT_ID_SPCS;

const SCOPE_RDI = process.env.SCOPE_RDI;
const SCOPE_IWPS = process.env.SCOPE_IWPS;
const SCOPE_APPTMOM = process.env.SCOPE_APPTMOM;
const SCOPE_CRM = process.env.SCOPE_CRM;

const SCOPE_ISPS = process.env.SCOPE_ISPS;
const SCOPE_SPCS = process.env.SCOPE_SPCS;

if (!JWKS_URL_RDI || !JWKS_URL_IWPS || !JWKS_URL_APPTMOM || !COGNITO_USER_POOL_ID || !CLIENT_ID_RDI || !CLIENT_ID_IWPS || !CLIENT_ID_APPTMOM) {
  throw new Error("Missing Cognito JWKS or Client ID environment variables");
}

// Cache JWKS keys to avoid frequent requests
let cachedKeys = {};

// 🔹 Lambda handler function
export const handler = async (event) => {
  try {
    console.log("Incoming event:", JSON.stringify(event, null, 2));

    // Normalize headers (in case-sensitive and case-insensitive combinations)
    const headers = event.headers || {};
    const authHeader = headers.authorization || headers.Authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return generateDeny("Missing or invalid token", event.methodArn);
    }

    // Extract token by removing "Bearer " prefix
    const token = authHeader.replace("Bearer ", "").trim();
    let decodedToken = jwt.decode(token, { complete: true });

    if (!decodedToken || !decodedToken.header || !decodedToken.header.kid) {
      return generateDeny("Missing Key ID (kid)", event.methodArn);
    }

    let kid = decodedToken.header.kid;
    let jwksUrl, expectedClientId,expectedScope;

    const path = (event.path || "").toLowerCase(); 

    // 🔹 Determine the correct JWKS URL & Client ID based on the request path
    if (path.includes("/rdi/")) {
      jwksUrl = JWKS_URL_RDI;
      expectedClientId = CLIENT_ID_RDI;
      expectedScope=SCOPE_RDI
    } else if (path.includes("/iwps/")) {
      jwksUrl = JWKS_URL_IWPS;
      expectedClientId = CLIENT_ID_IWPS;
      expectedScope=SCOPE_IWPS
    } else if (path.includes("/apptmom/api/")) {
      jwksUrl = JWKS_URL_APPTMOM;
      expectedClientId = CLIENT_ID_APPTMOM;
      expectedScope=SCOPE_APPTMOM
    } else if (path.includes("/crm/")) {
      jwksUrl = JWKS_URL_CRM;
      expectedClientId = CLIENT_ID_CRM;
      expectedScope=SCOPE_CRM
    } else if (path.includes("/isps/")) {
        jwksUrl = JWKS_URL_ISPS;
        expectedClientId = CLIENT_ID_ISPS;
        expectedScope=SCOPE_ISPS
    } else if (path.includes("/spcs/")) {
        jwksUrl = JWKS_URL_SPCS;
        expectedClientId = CLIENT_ID_SPCS;
        expectedScope=SCOPE_SPCS
    } else {
      return generateDeny("Invalid request path", event.methodArn);
    }

    console.log("Selected JWKS URL:", jwksUrl);
    let jwks = await getJWKSKeys(jwksUrl);

    console.log("JWKS retrieved:", jwks);
    console.log("jwks[kid]", jwks[kid]);
    console.log("kid", kid);

    if (!jwks[kid]) {
      console.error("JWT 'kid' not found in JWKS.");
      return generateDeny("Invalid Key ID", event.methodArn);
    }

    // ✅ Convert JWKS (n, e) to PEM format
    let pemKey = jwkToPem(jwks[kid]);

    // ✅ Verify JWT using the PEM public key
    let payload = jwt.verify(token, pemKey, { algorithms: ["RS256"] });
    console.log("Verified Token Payload:", JSON.stringify(payload, null, 2));

    // ✅ Validate Cognito issuer
    const expectedIssuer = `https://cognito-idp.ap-southeast-1.amazonaws.com/${COGNITO_USER_POOL_ID}`;
    if (payload.iss !== expectedIssuer) {
      return generateDeny("Invalid Token Issuer", event.methodArn);
    }

    console.log(`JWT 'client_id': ${payload.client_id || "MISSING"}`);
    console.log(`Expected Client ID: ${expectedClientId}`);
    

    // ✅ Validate Client ID
    if (!payload.client_id || payload.client_id !== expectedClientId) {
      return generateDeny(`Invalid Client ID (Expected: ${expectedClientId}, Got: ${payload.client_id || "MISSING"})`, event.methodArn);
    }

    console.log(`Expected scope: ${expectedScope}`);
    // ✅ Validate Client ID
    if (!payload.scope || payload.scope !== expectedScope) {
        return generateDeny(`Invalid scope (Expected: ${expectedScope}, Got: ${payload.scope || "MISSING"})`, event.methodArn);
      }

    // ✅ Token is valid, allow request
    return generateAllow(payload.sub, event.methodArn, payload);

  } catch (err) {
    console.error("Token Validation Failed:", err);

    if (err.name === "TokenExpiredError") {
      return generateDeny("Token Expired", event.methodArn);
    } else if (err.name === "JsonWebTokenError") {
      return generateDeny("Invalid Token", event.methodArn);
    } else {
      return generateDeny("Unauthorized", event.methodArn);
    }
  }
};

// 🔹 Fetch JWKS from Cognito URL (With Caching)
async function getJWKSKeys(jwksUrl) {
  if (!cachedKeys[jwksUrl] || Object.keys(cachedKeys[jwksUrl]).length === 0) {
    try {
      console.log("Fetching JWKS from URL:", jwksUrl);
      const response = await axios.get(jwksUrl);
      const keys = response.data.keys;

      cachedKeys[jwksUrl] = {};
      keys.forEach(key => {
        cachedKeys[jwksUrl][key.kid] = {
          kty: key.kty,
          n: key.n,
          e: key.e
        };
      });

      console.log("JWKS Keys Cached for:", jwksUrl);
    } catch (error) {
      console.error("Failed to fetch JWKS:", error);
      throw new Error("JWKS Fetch Failed");
    }
  }
  return cachedKeys[jwksUrl];
}

// ✅ Generate ALLOW IAM Policy
const generateAllow = (principalId, resource, context) => ({
  principalId,
  policyDocument: {
    Version: "2012-10-17",
    Statement: [{
      Action: "execute-api:Invoke",
      Effect: "Allow",
      Resource: resource
    }]
  },
  context
});

// ❌ Generate DENY IAM Policy
const generateDeny = (reason, resource) => ({
  principalId: "user",
  policyDocument: {
    Version: "2012-10-17",
    Statement: [{
      Action: "execute-api:Invoke",
      Effect: "Deny",
      Resource: resource
    }]
  },
  context: {
    errorMessage: reason
  }
});