# AWS ECS Orb

This is a Bluetel fork of the original CircleCI AWS ECS Orb.

<b>Important: This repo and the orbs are stored publicly. Do not commit ant secrets or sensitive information to this repo!</b>

## Installation

In development, we use `pipenv` to manage our Python dependencies. To install `pipenv`, run the following commands:

1. `brew install pipenv` # Install pipenv
2. `pipenv --python <your python3 path>` # Point to the correct python version
3. `pipenv install` # Install python dependencies

## Why?

This fork supports the auto-retrieval of the latest Secret version from AWS Secrets Manager. The secret version is then tied inside the task definition.

This way, secret changes cannot be made without a new deployment. This is important for security and audit purposes.

## Example 

```yaml
- aws-ecs/update_service:
    # ECS Configuration
    cluster: $ECS_CLUSTER_ARN
    service_name: $ECS_SERVICE_NAME
    family: $ECS_FAMILY_NAME

    # CodeDeploy Configuration
    deployment_controller: CODE_DEPLOY
    codedeploy_application_name: $ECS_DEPLOYMENT_APP_NAME
    codedeploy_deployment_group_name: $ECS_DEPLOYMENT_GROUP_NAME
    codedeploy_load_balanced_container_port: 8080
    codedeploy_load_balanced_container_name: NaFrontendNginx

    # Updates
    container_image_name_updates: >
      container=NaNextJs,tag=${CIRCLE_SHA1}-nextjs,
      container=NaApollo,tag=${CIRCLE_SHA1}-apollo
    
    bluetel_fix_secret_versions: RUNTIME_ENV,SECOND_ENV # The name of the secrets to tie to the latest version.
```

## Original Readme

[![CircleCI Build Status](https://circleci.com/gh/CircleCI-Public/aws-ecs-orb.svg?style=shield "CircleCI Build Status")](https://circleci.com/gh/CircleCI-Public/aws-ecs-orb) [![CircleCI Orb Version](https://badges.circleci.com/orbs/circleci/aws-ecs.svg)](https://circleci.com/orbs/registry/orb/circleci/aws-ecs) [![GitHub License](https://img.shields.io/badge/license-MIT-blue.svg)](https://raw.githubusercontent.com/CircleCI-Public/aws-ecs-orb/master/LICENSE) [![CircleCI Community](https://img.shields.io/badge/community-CircleCI%20Discuss-343434.svg)](https://discuss.circleci.com/c/ecosystem/orbs)


A CircleCI Orb to simplify deployments to Amazon Elastic Container Service (ECS). Supports EC2 and Fargate launch type deployments.

## Resources

[CircleCI Orb Registry Page](https://circleci.com/orbs/registry/orb/circleci/aws-ecs) - The official registry page of this orb for all versions, executors, commands, and jobs described.

[CircleCI Orb Docs](https://circleci.com/docs/2.0/orb-intro/#section=configuration) - Docs for using and creating CircleCI Orbs.

### Examples

Please visit the [orb registry listing](https://circleci.com/orbs/registry/orb/circleci/aws-ecs) for usage examples and guidelines.



### How to Contribute

We welcome [issues](https://github.com/CircleCI-Public/aws-ecs-orb/issues) to and [pull requests](https://github.com/CircleCI-Public/aws-ecs-orb/pulls) against this repository!


For further questions/comments about this or other orbs, visit the Orb Category of [CircleCI Discuss](https://discuss.circleci.com/c/orbs).

