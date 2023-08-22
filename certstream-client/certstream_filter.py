import requests
import tldextract
import whois
import boto3
import json
import certstream
import datetime

# Config settings
certstream_url = 'ws://127.0.0.1:4000'
domain_log = 'certstream_filter.txt'
AWS_REGION = "us-east-1"
maxlen = 25


# Add keywords for things you are interested in
keywords = {
    'particular',
    'directa',
    'banco'
}
# Add keywords for things you are ignoring
ignores = {
    'xn--'
}

# List with domains
longlist = set()

def publish_notification(notification):
    # Send notification to SNS
    client = boto3.client('sns', region_name=AWS_REGION)
    response = client.publish (
        TargetArn = "arn:aws:sns:us-east-1:178258615948:certstream-topic",
        Message = json.dumps({'default': notification}),
        MessageStructure = 'json'
    )

def telegram_notification(notification):
    # Send notification to Telegram channel
    TOKEN = get_secret("telegram/awscertstreambot", "token")
    chat_id = get_secret("telegram/awscertstreambot", "chat_id")
    url = f"https://api.telegram.org/bot{TOKEN}/sendMessage?chat_id={chat_id}&text={notification}"
    requests.get(url)


def get_secret(secret_name, key_name):
    # Get secret from Secret Manager

    # Create a Secrets Manager client
    session = boto3.session.Session()
    clientsecret = session.client(
        service_name='secretsmanager',
        region_name=AWS_REGION
    )

    # In this sample we only handle the specific exceptions for the 'GetSecretValue' API.
    # See https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
    # We rethrow the exception by default.

    try:
        get_secret_value_response = clientsecret.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'DecryptionFailureException':
            # Secrets Manager can't decrypt the protected secret text using the provided KMS key.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InternalServiceErrorException':
            # An error occurred on the server side.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            # You provided an invalid value for a parameter.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            # You provided a parameter value that is not valid for the current state of the resource.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'ResourceNotFoundException':
            # We can't find the resource that you asked for.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
    else:
        # Decrypts secret using the associated KMS key.
        # Depending on whether the secret is a string or binary, one of these fields will be populated.
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
            jsondata = json.loads(secret)
        else:
            decoded_binary_secret = base64.b64decode(get_secret_value_response['SecretBinary'])
            jsondata = json.loads(decoded_binary_secret)
        return jsondata[key_name]


def submiturlscan(link):
    # Submit link to URLSCAN.IO and return link to snapshot
    url = "https://urlscan.io/api/v1/scan/"
    headers = {"Content-Type": "application/json; charset=utf-8", "API-Key": get_secret("urlscan.io/api-key", "urlscan-api-key") }

    data = {
        "url": link.rstrip('\n'),
        "visibility": "public",
	"customagent": "Mozilla/5.0 (Linux; Android 11) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Mobile Safari/537.36"
       }

    response = requests.post(url, headers=headers, json=data)
    jsondata=response.json()

    if response.status_code == 200:
        result = link.rstrip('\n') + " urlscan: https://urlscan.io/screenshots/" + jsondata["uuid"] + ".png\n"
    else:
        result = link
    return result

def whois_is_recent(domain):
    # Checks if domain was registered in the last 30 days
    try:
        is_recent = False
        df = "%Y-%m-%d %H:%M:%S"  #(2002-10-30 00:00:00
        d = datetime.date.today().strftime(df)
        w = whois.whois(domain)
        dt = datetime.datetime.strptime(d,df)
        if type(w.creation_date) is list:
         cdt = w.creation_date[0]
        else:
         cdt = w.creation_date
        delta = dt - cdt
        if delta.days<= 30:
            is_recent = True
    except Exception:
        return False
    else:
        return is_recent

def whois_data(domain):
    # Gets WHOIS data for a domain
    df = "%Y-%m-%d %H:%M:%S"  #(2002-10-30 00:00:00

    try:
        d = datetime.date.today().strftime(df)
        w = whois.whois(domain)
        dt = datetime.datetime.strptime(d,df)

        if type(w.updated_date) is list:
         cdu = w.updated_date[0]
        else:
         cdu = w.updated_date

        delta = dt - cdu

    except Exception:
        result = "Domain: " + domain + " CDu: unknown Delta: unknown"
        return result

    else:
        result = "Domain: " + domain + " CDu: " + cdu.strftime("%m/%d/%Y") + " Delta: " + str(delta.days)
        #result = "Domain: " + domain + " CDt: " + cdt.strftime("%m/%d/%Y") + " CDu: " + cdu.strftime("%m/%d/%Y") + " Delta: " + str(delta.days)
        return result

def callback(message, context):
    # Callback handler for certstream events (boilerplate from CaliDog Github)
    if message['message_type'] == "heartbeat":
        return

    if message['message_type'] == "certificate_update":
        all_domains = message['data']['leaf_cert']['all_domains']

        for domain in all_domains:
            # Check maxsize
            if len(domain) > maxlen:
                continue

            # Check if ignore exists
            if any(kword in domain for kword in ignores):
                continue

            # Filter domain if we have already seen it (prevent duplication)
            if domain in longlist:
                continue
            longlist.add(domain)
            if len(longlist) > 10000000:
                telegram_notification(str(datetime.datetime.now()) + ': Domain list rotation')
                longlist.clear()
            
            # Check if keyword exists
            if any(kword in domain for kword in keywords):
                    print(str(datetime.datetime.now()) + ': ' + domain)
                    if whois_is_recent(domain):
                        if "*." in domain:
                            #notification = str(datetime.datetime.now()) + ': : ' + recent + ' : ' + domain
                            notification = str(datetime.datetime.now()) + ': ' + whois_data(domain) + ' : ' + domain
                        else:
                            #notification = str(datetime.datetime.now()) + ': : ' + recent + ' : ' + submiturlscan(domain)
                            notification = str(datetime.datetime.now()) + ': ' + whois_data(domain) + ' : ' + submiturlscan(domain)

                        # Send notification to SNS
                        publish_notification(notification)

                        # Send notification to telegram
                        telegram_notification(notification)


if __name__ == '__main__':
    certstream.listen_for_events(callback, url=certstream_url)
