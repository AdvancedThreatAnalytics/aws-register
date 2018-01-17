# aws-register

Simple python module to allow fetching IP addresses of instances in autoscaling
groups or ECS services and saving them to a route53 record.

## Usage

For full usage see `aws-register -h`

As well as a python package there is also a docker image you can use directly
in ECS:


    {
        "family": "redis-service",
        "containerDefinitions": [
            {
                "name": "redis-server",
                "image": "redis",
                "cpu": 10,
                "memory": 800,
                "essential": true,
                "portMappings": [
                    {
                        "containerPort": 6379,
                        "hostPort": 6379
                    }
                ]
            },
            {
                "name": "aws-register",
                "image": "advancedthreatanalytics/aws-register",
                "memory": 45,
                "command": ["--fqdn", "example.domain.com",
                            "--target", "ecs:ClusterName:redis-service",
                            "--rerun"],
                "essential": false
            }
        ]
    }
