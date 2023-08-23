
CERTSTREAM


Detecting phishing campains using certificate transparency logs and filtering by keywords.
Notification findings by:
- mail
  
![image](https://github.com/nmmstuff/certstream-aws/assets/142457788/d313915f-e3bc-4cd3-9219-ab0e636e150a)

- telegram
  
![image](https://github.com/nmmstuff/certstream-aws/assets/142457788/cb1b00c6-85ce-4b87-a5cb-7c51ea94df5d)

Fields:
- Date of the finding
- Domain - CN in the certificate
- CDu - Date of the last update made to whois information of domain
- Delta - Number of days since CDu
- urlscan - Url from urlscan.io with screenshot from the site
  
The purpose is to run the certstream-server docker and a custom certstream-client docker in an AWS ECS service (cost efficiency).

- certstream-server docker

Receives information from various certificate transparency logs and provide a stream of information.

Credits to "Cali Dog Security", developed in Elixir:
https://github.com/CaliDog/certstream-server

Requirements: Elixir installed (https://github.com/CaliDog/certstream-server/blob/master/README.md)

- certstream-client docker

Connects to the certstream-server and searchs for keyword on the certificate stream. If it finds one in a recent domain (domain registered/updated in the last 30 days), it will send a notification with the following information:
. date
. domain 
. whois date of update
. link with urlscan.io screenshot

Config: 
. List of keywords to search in certificate transparency logs in the code
. Correct aws sns topic ARN in code (needs improvement)

Integrations/Dependencies:
. whois - detect domain registered/updated recently
. urlscan.io - submit for evaluation and get a screenshot of the site
. telegram - send notifications to a telegram channel
. AWS SecretManager - guard api secrets
. AWS SNS topic - subscribe topic to receive email 

Setup:

- config "image" in docker-compose-aws.yml to AWS ECR 
- login to AWS ECR
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin <account>.dkr.ecr.us-east-1.amazonaws.com
- docker compose -f docker-compose-aws.yml build
- docker compose -f docker-compose-aws.yml push

ECS commands : 

aws ecs list-services --cluster "default"
aws ecs list-tasks --cluster "default" --service "certstream"
- enable da task no cluster ecs
aws ecs update-service --desired-count 1 --cluster "default" --service "certstream"
- disable da task no cluster ecs
aws ecs update-service --desired-count 0 --cluster "default" --service "certstream"


$ aws ecs describe-task-definition --task-definition "certstream"
{
    "taskDefinition": {
        "taskDefinitionArn": "arn:aws:ecs:us-east-1:178258615948:task-definition/certstream:4",
        "containerDefinitions": [
            {
                "name": "certstream-server",
                "image": "178258615948.dkr.ecr.us-east-1.amazonaws.com/certstream-server",
                "cpu": 0,
                "portMappings": [],
                "essential": true,
                "environment": [],
                "mountPoints": [],
                "volumesFrom": [],
                "logConfiguration": {
                    "logDriver": "awslogs",
                    "options": {
                        "awslogs-group": "/ecs/certstream",
                        "awslogs-region": "us-east-1",
                        "awslogs-stream-prefix": "ecs"
                    }
                }
            },
            {
                "name": "certstream-client",
                "image": "178258615948.dkr.ecr.us-east-1.amazonaws.com/certstream-client",
                "cpu": 0,
                "portMappings": [],
                "essential": true,
                "environment": [],
                "mountPoints": [],
                "volumesFrom": [],
                "logConfiguration": {
                    "logDriver": "awslogs",
                    "options": {
                        "awslogs-group": "/ecs/certstream",
                        "awslogs-region": "us-east-1",
                        "awslogs-stream-prefix": "ecs"
                    }
                }
            }
        ],
        "family": "certstream",
        "taskRoleArn": "arn:aws:iam::178258615948:role/ecsTaskSNSSecretRole",
        "executionRoleArn": "arn:aws:iam::178258615948:role/ecsTaskExecutionRole",
        "networkMode": "awsvpc",
        "revision": 4,
        "volumes": [],
        "status": "ACTIVE",
        "requiresAttributes": [
            {
                "name": "com.amazonaws.ecs.capability.logging-driver.awslogs"
            },
            {
                "name": "ecs.capability.execution-role-awslogs"
            },
            {
                "name": "com.amazonaws.ecs.capability.ecr-auth"
            },
            {
                "name": "com.amazonaws.ecs.capability.docker-remote-api.1.19"
            },
            {
                "name": "com.amazonaws.ecs.capability.task-iam-role"
            },
            {
                "name": "ecs.capability.execution-role-ecr-pull"
            },
            {
                "name": "com.amazonaws.ecs.capability.docker-remote-api.1.18"
            },
            {
                "name": "ecs.capability.task-eni"
            }
        ],
        "placementConstraints": [],
        "compatibilities": [
            "EC2",
            "FARGATE"
        ],
        "requiresCompatibilities": [
            "FARGATE"
        ],
        "cpu": "2048",
        "memory": "4096",
        "registeredAt": "2022-09-27T09:36:33.722000+00:00",
        "registeredBy": "arn:aws:iam::178258615948:user/xxxxxxx"
    },
    "tags": []
}

role/ecsTaskSNSSecretRole
- Allow SNS publish
- Allow Secret access

