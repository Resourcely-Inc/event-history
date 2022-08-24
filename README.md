
# Event History
This script counts the total number of resources created in the last 90 days in a specific AWS region.  
## Setup

### Dependencies
- Python >= 3.8
- Docker (optional)
### Credentials
We currently support loading credentials from:   
- environment variables
  - AWS_ACCESS_KEY_ID
  - AWS_SECRET_ACCESS_KEY
  - AWS_SESSION_TOKEN
- ~/.aws/credentials

### Policy
You need to have the credentials for a user with at least this policy:
```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "cloudtrail:LookupEvents"
            ],
            "Resource": "*"
        }
    ]
}
```
## Running Locally

Install Dependencies:
```
pip3 install -r requirements.txt
```
Run Script:
```
python3 main.py -r <region>
```
Regions are listed below in [Available Regions](#available-regions)

## Running Docker (will run in all regions)
Run: 
```
docker-compose up --build
```
## Example Resource Output
The output will be in results.csv, and will look like the example below:

|     | CreateBucket | CreateCluster | CreateRegistry | CreateSecurityGroup | CreateSubnet | CreateVpc | CreateTrail | UpdateTrail | UpdateAuthorizer | CreateDBInstance | CreateDBCluster | CreateInternetGateway | CreateNatGateway |     |     |     |     |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| cnfkt | 0   | 0   | 0   | 0   | 0   | 0   | 3   | 3   | 0   | 0   | 0   | 0   | 0   |
| jebdx | 0   | 0   | 0   | 0   | 0   | 0   | 2   | 1   | 0   | 0   | 0   | 0   | 0   |
| qpwag | 1   | 0   | 0   | 0   | 0   | 0   | 0   | 0   | 1   | 1   | 1   | 0   | 0   |
| uxrnt | 3   | 0   | 0   | 0   | 0   | 0   | 0   | 0   | 0   | 0   | 0   | 0   | 0   |
| yhaix | 0   | 1   | 1   | 1   | 4   | 1   | 0   | 0   | 0   | 0   | 0   | 2   | 3   |

## Example User Agent Output
| user_agent | num_resources |
| ---        | ---           |
| aws-sdk-go-v2/1.16.7 os/macos lang/go/1.18 md/GOOS/darwin md/GOARCH/arm64 api/iam/1.18.5 | 46  |
| aws-sdk-go/1.44.19 (go1.18; darwin; amd64)                                               | 32  |
| aws-sdk-go-v2/1.16.5 os/macos lang/go/1.18 md/GOOS/darwin md/GOARCH/arm64 api/iam/1.18.5 | 14  |
| AWS Internal                                                                             | 1   |
| aws-sdk-go/1.44.19 (go1.18; darwin; arm64)                                               | 8   |

## Available Regions
- all (runs all regions)
- af-south-1
- ap-east-1
- ap-northeast-1
- ap-northeast-2
- ap-northeast-3
- ap-south-1
- ap-southeast-2
- ap-southeast-1
- ca-central-1
- cn-north-1
- cn-northwest-1
- eu-central-1
- eu-north-1
- eu-west-1
- eu-west-2
- eu-west-3
- eu-south-1
- me-south-1
- sa-east-1
- us-gov-east-1
- us-gov-west-1
- us-east-1
- us-east-2
- us-west-1
- us-west-2