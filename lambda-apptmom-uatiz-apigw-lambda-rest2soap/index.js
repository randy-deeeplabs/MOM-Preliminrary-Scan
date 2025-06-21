const axios = require('axios');
const xml2js = require('xml2js');
const AWS = require('aws-sdk');
const https = require('https');

// Initialize AWS clients
const secretsManager = new AWS.SecretsManager();
const s3 = new AWS.S3();

// Fetch domains and cert info from environment variables
const IWPS_DOMAIN = process.env.IWPS_DOMAIN;
const RDI_DOMAIN = process.env.RDI_DOMAIN;
const CRM_DOMAIN = process.env.CRM_DOMAIN;

// Secret names
const SECRET_NAME_IWPS = 'soap/credentials/iwps';
const SECRET_NAME_RDI = 'rest/credentials/rdi';
const SECRET_NAME_CRM = 'rest/credentials/crm';
const SECRET_CERT_RDI ='rest/credentials/rdi-cert';

// Fetch credentials from Secrets Manager
async function getCredentials(secretName) {
  console.log("Fetching secret:", secretName);
  const secret = await secretsManager.getSecretValue({ SecretId: secretName }).promise();

  // Try parse only if it's valid JSON
  try {
    return JSON.parse(secret.SecretString);
  } catch (err) {
    // If not JSON, return the raw string
    return { pem: secret.SecretString };
  }
}

// Fetch CA cert from S3
async function getCaCertFromS3(bucket, key) {
  console.log("Fetching CA certificate from S3:", bucket, key);
  const data = await s3.getObject({ Bucket: bucket, Key: key }).promise();
  const caCert = data.Body.toString('utf-8');
  console.log("CA certificate fetched, size:", caCert.length);
  return caCert;
}

// Converts xsi:nil="true" XML elements into null
function cleanField(value) {
  if (
    value &&
    typeof value === 'object' &&
    '$' in value &&
    (value['$']['xsi:nil'] === 'true' || value['$']['xsi:nil'] === true)
  ) {
    return null;
  }
  return value ?? null;
}

exports.handler = async (event) => {
  try {
    console.log('Incoming event:', JSON.stringify(event, null, 2));
    const requestPath = event.path;

    let secretName, serviceUrl, response;

    if (requestPath.includes('/iwps/')) {
      // IWPS SOAP call
      secretName = SECRET_NAME_IWPS;
      serviceUrl = `${IWPS_DOMAIN}/IAppointmentServiceSoap`;
      console.log("Calling IWPS SOAP service:", serviceUrl);

      const credentials = await getCredentials(secretName);
      const USERNAME = credentials.username;
      const PASSWORD = credentials.password;

      let body;
      try {
        body = typeof event.body === "string" ? JSON.parse(event.body) : event.body;
      } catch (e) {
        console.error("Invalid JSON body:", e);
        return { statusCode: 400, body: JSON.stringify({ message: "Invalid JSON body" }) };
      }

      if (body.Appointment) {
        body = body.Appointment;
      }

      if (!body.AppointmentPurposeID || !Array.isArray(body.Attendees)) {
        return { statusCode: 400, body: JSON.stringify({ message: "Missing AppointmentPurposeID or Attendees" }) };
      }

      const soapRequest = `
        <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
          <soap:Header/>
          <soap:Body>
            <Appointment xmlns="http://mom.gov.sg/iappointment/service/request/">
              <AppointmentPurposeID>${body.AppointmentPurposeID}</AppointmentPurposeID>
              <Attendees>
                ${body.Attendees.map((a) => `<Attendee><FIN>${a.FIN}</FIN></Attendee>`).join('')}
              </Attendees>
            </Appointment>
          </soap:Body>
        </soap:Envelope>
      `;

      console.log("SOAP Request XML:", soapRequest);

      response = await axios.post(serviceUrl, soapRequest, {
        headers: {
          'Content-Type': 'text/xml; charset=utf-8',
          'SOAPAction': '""',
          Authorization: 'Basic ' + Buffer.from(`${USERNAME}:${PASSWORD}`).toString('base64')
        },
        httpsAgent: new https.Agent({ rejectUnauthorized: false })
      });

      const parsedResponse = await xml2js.parseStringPromise(response.data, {
        explicitArray: false,
        tagNameProcessors: [xml2js.processors.stripPrefix]
      });

      console.log("Parsed SOAP Response:", JSON.stringify(parsedResponse, null, 2));

      const envelope = parsedResponse.Envelope;
      const responseBody = envelope?.Body;
      const appointment = responseBody?.Appointment;

      if (!appointment) {
        return { statusCode: 500, body: JSON.stringify({ message: "Appointment not found in SOAP response" }) };
      }

      let attendees = appointment.Attendees?.Attendee || [];

      if (!Array.isArray(attendees)) {
        attendees = [attendees];
      }

      const jsonResponse = {
        Appointment: {
          AppointmentPurposeID: parseInt(appointment.AppointmentPurposeID, 10),
          Attendees: attendees.map((a) => ({
            FIN: cleanField(a.FIN),
            IsDependentRequired: a.IsDependentRequired === 'true',
            IsEligible: a.IsEligible === 'true',
            CustomerName: cleanField(a.CustomerName),
            DateOfApplication: cleanField(a.DateOfApplication),
            Gender: cleanField(a.Gender),
            Nationality: cleanField(a.Nationality),
            MobilePhone: cleanField(a.MobilePhone),
            Email: cleanField(a.Email),
            AddressBlockNo: cleanField(a.AddressBlockNo),
            AddressStreet: cleanField(a.AddressStreet),
            AddressFloorUnitNo: cleanField(a.AddressFloorUnitNo),
            AddressBuilding: cleanField(a.AddressBuilding),
            AddressPostCode: cleanField(a.AddressPostCode),
            AddressCountry: cleanField(a.AddressCountry),
            LastModifiedDatetime: cleanField(a.LastModifiedDatetime),
            PassStatus: cleanField(a.PassStatus),
            PassExpiryDate: cleanField(a.PassExpiryDate),
            Passport: cleanField(a.Passport),
            PassType: cleanField(a.PassType),
            ErrMessage: cleanField(a.ErrMessage),
            EmployerName: cleanField(a.EmployerName),
            IndustrySector: cleanField(a.IndustrySector),
            DateOfIssue: cleanField(a.DateOfIssue),
            DateOfRenew: cleanField(a.DateOfRenew),
            DateOfIssuanceTransaction: cleanField(a.DateOfIssuanceTransaction),
            DateOfRenewalTransaction: cleanField(a.DateOfRenewalTransaction)
          }))
        }
      };

      return {
        statusCode: 200,
        body: JSON.stringify(jsonResponse, null, 2)
      };

    } else if (requestPath.includes('/rdi/')) {
      // RDI REST call
      secretName = SECRET_NAME_RDI;
      secretCertName=SECRET_CERT_RDI
      const rdiPath = requestPath.split('/rdi/')[1];
      if (!rdiPath) {
        return { statusCode: 400, body: JSON.stringify({ message: 'Invalid RDI request path' }) };
      }
    
      serviceUrl = `${RDI_DOMAIN}/${rdiPath}`;

      // Append query string if any
      const rawParams = event.queryStringParameters;
      console.log("rawParams: ",rawParams);
      if (rawParams && Object.keys(rawParams).length > 0) {
        const cleanParams = {};

        Object.keys(rawParams).forEach((key) => {
          // Remove any non-ASCII characters from the key
          const cleanedKey = key.replace(/[^\x20-\x7E]/g, '').trim(); // only printable ASCII
          cleanParams[cleanedKey] = rawParams[key];
        });

        const queryString = new URLSearchParams(cleanParams).toString();
        console.log("queryString:",queryString);
        serviceUrl += `?${queryString}`;
        console.log("Final RDI service URL with query:", serviceUrl);
      }
    
      const credentials = await getCredentials(secretName);
      const USERNAME = credentials.username;
      const PASSWORD = credentials.password;
      //const caCert=credentials.cert;
      const certSecret = await getCredentials(secretCertName);
      const caCert = certSecret.pem || certSecret.cert;
    //   const caCert = await getCaCertFromS3(CACERT_BUCKET, CACERT_KEY);
      console.log("start sending request to rdi",serviceUrl);
      response = await axios({
        method: event.httpMethod,
        url: serviceUrl,
        headers: {
          'Content-Type': 'application/json',
          requestor: USERNAME,
          requestorkey: PASSWORD
        },
        data: event.body ? (typeof event.body === "string" ? JSON.parse(event.body) : event.body) : undefined,
        httpsAgent: new https.Agent({
          ca: caCert,
          rejectUnauthorized: true // consider true in production
        })
      });
      console.log("response",response);
    
      return {
        statusCode: response.status,
        body: JSON.stringify(response.data)
      };
    } else if (requestPath.includes('/crm/')) {
      // CRM REST call
      secretName = SECRET_NAME_CRM;
      crmPath = requestPath.split('/crm/')[1];
      console.log("crmPath: ", crmPath);
      if (!crmPath) {
        return { statusCode: 400, body: JSON.stringify({ message: 'Invalid CRM request path' }) };
      }
      crmPath = crmPath.replace(/^\/?api\/v1/, 'apiv1/crm');
      console.log("crmPath: ", crmPath);
      serviceUrl = `${CRM_DOMAIN}/${crmPath}`;
      console.log("serviceUrl: ", serviceUrl);

      // Append query string if any
      const rawParams = event.queryStringParameters;
      console.log("rawParams: ",rawParams);
      if (rawParams && Object.keys(rawParams).length > 0) {
        const cleanParams = {};

        Object.keys(rawParams).forEach((key) => {
          // Remove any non-ASCII characters from the key
          const cleanedKey = key.replace(/[^\x20-\x7E]/g, '').trim(); // only printable ASCII
          cleanParams[cleanedKey] = rawParams[key];
        });

        const queryString = new URLSearchParams(cleanParams).toString();
        console.log("queryString:",queryString);
        serviceUrl += `?${queryString}`;
        console.log("Final CRM service URL with query:", serviceUrl);
      }
    
      const credentials = await getCredentials(secretName);
      const APIKEY = credentials.apikey;
      console.log("start sending request to crm",serviceUrl);
      const response = await axios({
        method: event.httpMethod,
        url: serviceUrl, // example: https://your-api-id.execute-api.ap-southeast-1.amazonaws.com/prod/resource
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': APIKEY
        },
        data: event.body ? (typeof event.body === "string" ? JSON.parse(event.body) : event.body) : undefined
      });
      console.log("crm response",response);
    
      return {
        statusCode: response.status,
        body: JSON.stringify(response.data)
      };
    } else {
      return { statusCode: 400, body: JSON.stringify({ message: 'Invalid request path' }) };
    }
  } catch (error) {
    console.error("Error during request:", error);
    return {
      statusCode: 500,
      body: JSON.stringify({ message: "Error processing request", error: error.message })
    };
  }
};