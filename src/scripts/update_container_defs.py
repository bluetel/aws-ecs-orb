from __future__ import absolute_import
import sys
import json
import boto3
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
    # Godsend for formatting the ARN:
    # https://docs.aws.amazon.com/AmazonECS/latest/developerguide/secrets-envvar-secrets-manager.html
    # TLDR:
    # arn:aws:secretsmanager:region:aws_account_id:secret:secret-name:json-key:version-stage:version-id
    if json_key:
        latest_version_arn = f"{base_secret_arn}:{json_key}::{latest_version_id}"
    else:
        latest_version_arn = f"{base_secret_arn}:::{latest_version_id}"
    
    return latest_version_arn


def unwrap_auto_versioned_secrets(secret_updates):
    """
    Unwraps the Bluetel fix secret versions from the container secrets update string.
    :param secret_updates: The container secrets update string.
    :return: List string of unwrapped secret updates.
    """
    if not secret_updates:
        return []
    
    return secret_updates.split(',')


# shellcheck disable=SC1036  # Hold-over from previous iteration.
def run(previous_task_definition, container_image_name_updates,
        container_env_var_updates, container_secret_updates, container_docker_label_updates,
        auto_versioned_secrets):
    try:
        definition = json.loads(previous_task_definition)
        container_definitions = definition['taskDefinition']['containerDefinitions']
    except:
        raise Exception('No valid task definition found: ' + previous_task_definition)

    # Build a map of the original container definitions so that the
    # array index positions can be easily looked up
    container_map = {}
    for index, container_definition in enumerate(container_definitions):
        env_var_map = {}
        env_var_definitions = container_definition.get('environment')
        if env_var_definitions is not None:
            for env_var_index, env_var_definition in enumerate(env_var_definitions):
                env_var_map[env_var_definition['name']] = {'index': env_var_index}
        secret_map = {}
        secret_definitions = container_definition.get('secrets')
        if secret_definitions is not None:
            for secret_index, secret_definition in enumerate(secret_definitions):
                secret_map[secret_definition['name']] = {'index': secret_index}
        container_map[container_definition['name']] = {'image': container_definition['image'], 'index': index, 'environment_map': env_var_map, 'secret_map': secret_map}

    # Expected format: container=...,name=...,value=...,container=...,name=...,value=
    try:
        env_kv_pairs = container_env_var_updates.split(',')
        for index, kv_pair in enumerate(env_kv_pairs):
            kv = kv_pair.split('=')
            key = kv[0].strip()

            if key == 'container':
                container_name = kv[1].strip()
                env_var_name_kv = env_kv_pairs[index+1].split('=')
                env_var_name = env_var_name_kv[1].strip()
                env_var_value_kv = env_kv_pairs[index+2].split('=', maxsplit=1)
                env_var_value = env_var_value_kv[1].strip()
                if env_var_name_kv[0].strip() != 'name' or env_var_value_kv[0].strip() != 'value':
                    raise ValueError(
                        'Environment variable update parameter format is incorrect: ' + container_env_var_updates)

                container_entry = container_map.get(container_name)
                if container_entry is None:
                    raise ValueError('The container ' + container_name + ' is not defined in the existing task definition')
                container_index = container_entry['index']
                env_var_entry = container_entry['environment_map'].get(env_var_name)
                if env_var_entry is None:
                    # The existing container definition does not contain environment variables
                    if container_definitions[container_index].get('environment') is None:
                        container_definitions[container_index]['environment'] = []
                    # This env var does not exist in the existing container definition
                    container_definitions[container_index]['environment'].append({'name': env_var_name, 'value': env_var_value})
                else:
                    env_var_index = env_var_entry['index']
                    container_definitions[container_index]['environment'][env_var_index]['value'] = env_var_value
            elif key and key not in ['container', 'name', 'value']:
                raise ValueError('Incorrect key found in environment variable update parameter: ' + key)
    except ValueError as value_error:
        raise value_error
    except:
        raise Exception('Environment variable update parameter could not be processed; please check parameter value: ' + container_env_var_updates)

    # Expected format: container=...,string=...,string=...,container=...,string=...,string=
    
    try:
        docker_label_kv_pairs = container_docker_label_updates.split(',')
        for index, kv_pair in enumerate(docker_label_kv_pairs):
            kv = kv_pair.split('=')
            key = kv[0].strip()

            if key == 'container':
                container_name = kv[1].strip()
                docker_label_kv = docker_label_kv_pairs[index+1].split('=')
                docker_label_key = docker_label_kv[0].strip()
                docker_label_value = docker_label_kv[1].strip()
                container_entry = container_map.get(container_name)
                if container_entry is None:
                    raise ValueError('The container ' + container_name + ' is not defined in the existing task definition')
                container_index = container_entry['index']
                docker_label_entry = container_entry['environment_map'].get(docker_label_key)
                if docker_label_entry is None:
                    # The existing container definition does not contain environment variables
                    if container_definitions[container_index].get('dockerLabels') is None:
                        container_definitions[container_index]['dockerLabels'] = {}
                    # This env var does not exist in the existing container definition
                    container_definitions[container_index]['dockerLabels'][docker_label_key] =  docker_label_value
                else:
                    docker_label_index = docker_label_entry['index']
                    container_definitions[container_index]['dockerLabels'][docker_label_index][docker_label_key] = docker_label_value
    except ValueError as value_error:
        raise value_error
    except:
        raise Exception('Docker label update parameter could not be processed; please check parameter value: ' + container_docker_label_updates)

    # Expected format: container=...,name=...,valueFrom=...,container=...,name=...,valueFrom=...

    try:
        secret_kv_pairs = container_secret_updates.split(',')
        for index, kv_pair in enumerate(secret_kv_pairs):
            kv = kv_pair.split('=')
            key = kv[0].strip()
            if key == 'container':
                container_name = kv[1].strip()
                secret_name_kv = secret_kv_pairs[index+1].split('=')
                secret_name = secret_name_kv[1].strip()
                secret_value_kv = secret_kv_pairs[index+2].split('=', maxsplit=1)
                secret_value = secret_value_kv[1].strip()
                if secret_name_kv[0].strip() != 'name' or secret_value_kv[0].strip() != 'valueFrom':
                    raise ValueError(
                        'Container secret update parameter format is incorrect: ' + container_secret_updates)

                container_entry = container_map.get(container_name)
                if container_entry is None:
                    raise ValueError('The container ' + container_name + ' is not defined in the existing task definition')
                container_index = container_entry['index']
                secret_entry = container_entry['secret_map'].get(secret_name)
                if secret_entry is None:
                    # The existing container definition does not contain secrets variable
                    if container_definitions[container_index].get('secrets') is None:
                        container_definitions[container_index]['secrets'] = []
                    # The secrets variable does not exist in the existing container definition
                    container_definitions[container_index]['secrets'].append({'name': secret_name, 'valueFrom': secret_value})
                else:
                    secret_index = secret_entry['index']
                    container_definitions[container_index]['secrets'][secret_index]['valueFrom'] = secret_value
            elif key and key not in ['container', 'name', 'valueFrom']:
                raise ValueError('Incorrect key found in secret updates parameter: ' + key)
    except ValueError as value_error:
        raise value_error
    except:
        raise Exception('Container secrets update parameter could not be processed; please check parameter value: ' + container_secret_updates)

    # Expected format: container=...,image-and-tag|image|tag=...,container=...,image-and-tag|image|tag=...,
    try:
        if container_image_name_updates and "container=" not in container_image_name_updates:
            raise ValueError('The container parameter is required in the container_image_name_updates variable.')

        image_kv_pairs = container_image_name_updates.split(',')
        for index, kv_pair in enumerate(image_kv_pairs):
            kv = kv_pair.split('=')
            key = kv[0].strip()
            if key == 'container':
                container_name = kv[1].strip()
                image_kv = image_kv_pairs[index+1].split('=')
                container_entry = container_map.get(container_name)
                if container_entry is None:
                    raise ValueError('The container ' + container_name + ' is not defined in the existing task definition')
                container_index = container_entry['index']
                image_specifier_type = image_kv[0].strip()
                image_value = image_kv[1].strip()
                if image_specifier_type == 'image-and-tag':
                    container_definitions[container_index]['image'] = image_value
                else:
                    existing_image_name_tokens = container_entry['image'].split(':')
                    if image_specifier_type == 'image':
                        tag = ''
                        if len(existing_image_name_tokens) == 2:
                            tag = ':' + existing_image_name_tokens[1]
                        container_definitions[container_index]['image'] = image_value + tag
                    elif image_specifier_type == 'tag':
                        container_definitions[container_index]['image'] = existing_image_name_tokens[0] + ':' + image_value
                    else:
                        raise ValueError(
                            'Image name update parameter format is incorrect: ' + container_image_name_updates)
            elif key and key not in ['container', 'image', 'image-and-tag', 'tag']:
                raise ValueError('Incorrect key found in image name update parameter: ' + key)

    except ValueError as value_error:
        raise value_error
    except:
        raise Exception('Image name update parameter could not be processed; please check parameter value: ' + container_image_name_updates)

    # Loop through the container definitions and see if there are any env var matches that are in the
    # auto_versioned_secrets list.

    auto_versioned_secrets = unwrap_auto_versioned_secrets(auto_versioned_secrets)

    try:
        for container_definition in container_definitions:
            # Check if the container definition has a secrets list
            if 'secrets' in container_definition:
                # Loop through the secrets list
                for secret in container_definition['secrets']:
                    # Check if the secret name is in the auto_versioned_secrets list
                    if secret['name'] in auto_versioned_secrets:
                        # Update the secret value to the latest version
                        secret['valueFrom'] = get_latest_secret_version(secret['valueFrom'])
    except Exception as e:
        raise Exception(f"Error updating Bluetel secret versions: {e}")

    return json.dumps(container_definitions)


if __name__ == '__main__':
    try:
        print(run(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6]))
    except Exception as e:
        sys.stderr.write(str(e) + "\n")
        exit(1)
