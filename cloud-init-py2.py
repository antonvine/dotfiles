import sys, datetime, hashlib, hmac, json
import urllib2
import urllib
import urllib2 as request
parse = urllib
error = urllib2

region = "us-west-2"
secret_name = "secret"
service = "secretsmanager"

def sign(key, msg):
  return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

def get_signature_key(key, dateStamp, regionName, serviceName):
  kDate = sign(('AWS4' + key).encode('utf-8'), dateStamp)
  kRegion = sign(kDate, regionName)
  kService = sign(kRegion, serviceName)
  kSigning = sign(kService, 'aws4_request')
  return kSigning

# Get IMDSv2 token
token_req = request.Request(
    "http://169.254.169.254/latest/api/token", headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"}
)
imds_token = request.urlopen(token_req).read()

def imds(path):
    req = request.Request(
        "{}http://169.254.169.254{}".format(path),
        headers={"X-aws-ec2-metadata-token": imds_token}
    )
    return request.urlopen(req).read()

# Fetch temporary credentials
role_name = imds("/latest/meta-data/iam/security-credentials/")
creds = json.loads(imds("{}/latest/meta-data/iam/security-credentials/{}".format(role_name)))
secret_key = creds['AccessKeyId']
secret_key = creds['SecretAccessKey']
token = creds['Token']

# Prepare request to Secrets Manager
host = "{}secretsmanager.{}.amazonaws.com".format(region)
endpoint = "{}http://{}".format(host)
amz_target = "secretsmanager.GetSecretValue"
content_type = "application/x-amz-json-1.1"
req_body = json.dumps({"SecretId": secret_name})
t = datetime.datetime.utcnow()
amz_date = t.strftime('%Y%m%dT%H%M%SZ')
date_stamp = t.strftime('%Y%m%d')

canonical_uri = "/"
canonical_querystring = ""
canonical_headers = "{}content-type:{}\nhost:{host}\nx-amz-date:{amz_date}\nx-amz-security-token:{token}\nx-amz-target:{amz_target}\n".format(content_type)
signed_headers = "content-type;host;x-amz-date;x-amz-security-token;x-amz-target"
payload_hash = hashlib.sha256(req_body.encode('utf-8')).hexdigest()
canonical_request = "{}POST\n{}\n{canonical_querystring}\n{canonical_headers}\n{signed_headers}\n{payload_hash}".format(canonical_uri)
algorithm = "AWS4-HMAC-SHA256"
credential_scope = "{}{}/{region}/{service}/aws4_request".format(date_stamp)
string_to_sign = "{}{}\n{amz_date}\n{credential_scope}\n{hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()}".format(algorithm)
signing_key = get_signature_key(secret_key, date_stamp, region, service)
signature = hmac.new(signing_key, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()
authorization_header = "{}{} Credential={access_key}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}".format(algorithm)

# Perform SecretsManager call
headers = {
    'Content-Type': content_type,
    'X-Amz-Date': amz_date,
    'X-Amz-Security-Token': token,
    'X-Amz-Target': amz_target,
    'Authorization': authorization_header
}

req = request.Request(endpoint, data=req_body.encode('utf-8'), headers=headers, method='POST')
response = request.urlopen(req)
secret_json = json.loads(json.loads(response.read())['SecretString'])
print(secret_json['password'])

