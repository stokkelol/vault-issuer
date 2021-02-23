import json
import botocore.session
import requests
import base64
import urllib3
import sys

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

PRIVATE_KEY_PATH = "/tmp/key.pem"
PUBLIC_KEY_PATH = "/tmp/crt.pem"


def issue_certificate():
    session = botocore.session.get_session()
    client = session.create_client('sts')
    endpoint = client._endpoint
    operation_model = client._service_model.operation_model('GetCallerIdentity')
    request_dict = client._convert_to_request_dict({}, operation_model)

    request = endpoint.create_request(request_dict, operation_model)
    headers = request.headers
    del(headers["Content-Length"])
    req_body = {
        "role": "vault-issuer-role",
        "max-ttl": "1m",
        "iam_http_request_method": request.method,
        "iam_request_url": base64.b64encode(request.url.encode()),
        "iam_request_body": base64.b64encode(request.body.encode()),
        "iam_request_headers": base64.b64encode(json.dumps({k: v.decode("utf-8") for k, v in headers.items()}).encode())
    }

    try:
        resp = requests.put(url='https://vault.service.consul:8200/v1/auth/aws/login', data=req_body, verify=False)
    except requests.ConnectionError as e:
        print(e)
        sys.exit()

    if resp.status_code != 200:
        print("auth error")
        print(resp.status_code)
        print(json.loads(resp.content))
        sys.exit()

    body = json.loads(resp.content)
    token = body['auth']['client_token']
    data = json.dumps({
        "ttl": "720h",
        "common_name": "client-certificate"
    })
    headers = {
        "X-Vault-Token": token,
        "Content-Type": "application/json"
    }

    try:
        resp = requests.put(url='https://vault.service.consul:8200/v1/pki/issue/vault-issuer-role', data=data,
                            verify=False, headers=headers)
    except requests.ConnectionError as e:
        print(e)
        sys.exit()

    if resp.status_code != 200:
        print("issue error")
        print(resp.status_code)
        print(json.loads(resp.content))
        sys.exit()

    body = json.loads(resp.content)

    public_key = body['data']['certificate']
    private_key = body['data']['private_key']

    with open(PRIVATE_KEY_PATH, 'w') as file:
        file.write(private_key)

    with open(PUBLIC_KEY_PATH, 'w') as file:
        file.write(public_key)


if __name__ == '__main__':
    issue_certificate()

