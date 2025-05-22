import boto3
import json
import re
import uuid

def get_latest_secret_version(secret_arn: str) -> str:
    """
    Get the latest version of a secret from AWS Secrets Manager. This does not
    return the latest tagged version, but the latest version of the secret.

    Args:
        secret_arn (str): The ARN of the secret to retrieve.

    Returns:
        str: The arn of the latest version of the secret.
    """
    
    # Pattern to detect UUID-like segments that could be version IDs
    uuid_pattern = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
    
    # Base pattern to extract the main secret ARN
    base_pattern = r'^(arn:aws:secretsmanager:[^:]+:[^:]+:secret:[^:]+)'
    
    # Extract the base ARN without any additional segments
    match = re.match(base_pattern, secret_arn)
    if not match:
        raise ValueError(f"Invalid secret ARN format: {secret_arn}")
    
    base_secret_arn = match.group(1)
    
    # Check if there's a JSON key in the ARN (not a UUID)
    remaining = secret_arn[len(base_secret_arn):].lstrip(':')
    segments = remaining.split(':')
    
    json_key = None
    if segments and segments[0] and not re.match(uuid_pattern, segments[0]):
        json_key = segments[0]
    
    # Create a Secrets Manager client
    session = boto3.session.Session()
    region = session.region_name or "ap-northeast-1"
    client = boto3.client('secretsmanager', region_name=region)

    # Get information about the versions of the secret
    response = client.list_secret_version_ids(
        SecretId=base_secret_arn
    )
    
    # Find the current version ID
    latest_version_id = None
    for version in response['Versions']:
        if version.get('VersionStages') and 'AWSCURRENT' in version['VersionStages']:
            latest_version_id = version['VersionId']
            break

    if not latest_version_id:
        raise ValueError(f"Could not find current version for secret: {base_secret_arn}")
    
    # Construct and return the ARN for the latest version with proper formatting
    if json_key:
        # Include empty version-stage slot (::) before version ID when using JSON key
        latest_version_arn = f"{base_secret_arn}:{json_key}::{latest_version_id}"
    else:
        latest_version_arn = f"{base_secret_arn}:{latest_version_id}"
    
    return latest_version_arn
