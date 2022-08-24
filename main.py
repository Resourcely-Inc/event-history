import logging
import boto3
from collections import defaultdict
import datetime
from pydantic import BaseModel, EmailStr
from typing import List, Optional, Any, Dict
from mypy_boto3_cloudtrail import CloudTrailClient
import pandas as pd
from mypy_boto3_cloudtrail.type_defs import LookupEventsResponseTypeDef
import argparse
import random
import string
import json
import csv

# configuration
AWS_REGION = "us-west-2"
CLOUDTRAIL_EVENT_HISTORY_DAYS = 90

# Set up AWS credentials, otherwise it will read from ~/.aws/credentials
aws_access_key_id = ("",)
aws_secret_access_key = ""

# logger config
logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s: %(levelname)s: %(message)s"
)
logging.getLogger().setLevel(logging.INFO)


# pydantic model
class Event(BaseModel):
    Function: str
    Resources: List[str] = []


class Identity(BaseModel):
    Name: str
    Type: str


class EventSourceEvent(BaseModel):
    Identity: Identity
    Events: List[Event] = []


class EventQueueLookupMessage(BaseModel):
    Events: List[EventSourceEvent] = []


class ResourcesEvent(BaseModel):
    ResourceType: str
    ResourceName: Optional[str]


class EventHistory(BaseModel):
    # attributes
    EventId: str
    ReadOnly: bool
    AccessKeyId: str
    EventTime: datetime.date
    EventSource: str
    Username: str
    EventName: str
    Resources: List[ResourcesEvent]
    CloudTrailEvent: str


Regions = [
    "all",
    "af-south-1",
    "ap-east-1",
    "ap-northeast-1",
    "ap-northeast-2",
    "ap-northeast-3",
    "ap-south-1",
    "ap-southeast-2",
    "ap-southeast-1",
    "ca-central-1",
    "cn-north-1",
    "cn-northwest-1",
    "eu-central-1",
    "eu-north-1",
    "eu-west-1",
    "eu-west-2",
    "eu-west-3",
    "eu-south-1",
    "me-south-1",
    "sa-east-1",
    "us-gov-east-1",
    "us-gov-west-1",
    "us-east-1",
    "us-east-2",
    "us-west-1",
    "us-west-2",
]

eventActions = [
    "CreateApi",
    "UpdateApi",
    "CreateBucket",
    "UpdateBucket",
    "CreateCertificate",
    "UpdateCertificate",
    "CreateCluster",
    "UpdateCluster",
    "CreateClusterV2",
    "CreateDeployment",
    "UpdateDeployment",
    "CreateDomain",
    "UpdateDomain",
    "CreateDomainName",
    "UpdateDomainName",
    "CreateFargateProfile",
    "CreateFirewall",
    "UpdateFirewallConfig",
    "CreateGateway",
    "UpdateGateway",
    "CreateHsm",
    "CreateImage",
    "UpdateImage",
    "CreateInstance",
    "UpdateInstance",
    "CreateLoadBalancer",
    "UpdateLoadBalancer",
    "CreateNetwork",
    "UpdateNetwork",
    "CreateRegistry",
    "UpdateRegistry",
    "CreateDataSourceFromRDS",
    "CreateLogStream",
    "CreateRestApi",
    "UpdateRestApi",
    "CreateRole",
    "UpdateRole",
    "CreateSecurityGroup",
    "CreateSnapshot",
    "UpdateSnapshot",
    "CreateSubnetGroup",
    "UpdateSubnetGroup",
    "CreateSubnet",
    "CreateUserPool",
    "CreateVpc",
    "CreateVolume",
    "UpdateVolume",
    "CreateVpcLink",
    "UpdateVpcLink",
    "CreateVpcPeeringConnection",
    "CreateFunction",
    "UpdateFunction",
    "CreateQueue",
    "UpdateQueue",
    "CreateTopic",
    "CreateTrail",
    "UpdateTrail",
    "CreateUserPoolClient",
    "UpdateUserPoolClient",
    "CreateApiMapping",
    "UpdateApiMapping",
    "CreateAuthorizer",
    "UpdateAuthorizer",
    "CreateDBInstance",
    "CreateDBCluster",
    "CreateEmailIdentity",
    "CreateIdentityProvider",
    "UpdateIdentityProvider",
    "CreateInternetGateway",
    "CreateKey",
    "CreateNatGateway",
    "CreateSecret",
    "UpdateSecret",
]

# logic
class EventHandler(BaseModel):

    events: List[EventHistory] = []

    @staticmethod
    def process_inputs() -> str:
        parser = argparse.ArgumentParser(description="Process AWS Region.")

        parser.add_argument(
            "-r",
            "--region",
            dest="aws_region",
            help="Process AWS Region.",
            metavar="REGION",
        )
        args = parser.parse_args()
        return args.aws_region

    @classmethod
    def lookup_events(cls, region) -> List[LookupEventsResponseTypeDef]:
        logger.info(f"Looking up events in {region}")
        client: CloudTrailClient = boto3.client(
            "cloudtrail",
            region_name=region,
            # aws_access_key_id=aws_access_key_id,
            # aws_secret_access_key=aws_secret_access_key
        )
        start_time = datetime.datetime.now() - datetime.timedelta(
            int(CLOUDTRAIL_EVENT_HISTORY_DAYS)
        )
        end_time = datetime.datetime.now()
        event_list: List[LookupEventsResponseTypeDef] = []
        for event in eventActions:
            next_token = ""
            iteration = 0
            while next_token != "" or iteration == 0:
                if next_token:
                    response: LookupEventsResponseTypeDef = client.lookup_events(
                        LookupAttributes=[
                            {"AttributeKey": "EventName", "AttributeValue": event},
                        ],
                        StartTime=start_time,
                        EndTime=end_time,
                        MaxResults=50,
                        NextToken=next_token,
                    )
                else:
                    response = client.lookup_events(
                        LookupAttributes=[
                            {"AttributeKey": "EventName", "AttributeValue": event},
                        ],
                        StartTime=start_time,
                        EndTime=end_time,
                        MaxResults=50,
                    )
                next_token = response.get("NextToken", "")
                iteration+=1
                event_list.append(response)
        return event_list

    @classmethod
    def create_events_object(cls, region) -> List[EventHistory]:
        event_list: List[LookupEventsResponseTypeDef] = cls.lookup_events(region)
        events: List[EventHistory] = [
            EventHistory(
                EventId=item.get("EventId", ""),
                EventName=item.get("EventName", ""),
                ReadOnly=bool(item.get("ReadOnly", "")),
                AccessKeyId=item.get("AccessKeyId", ""),
                EventTime=item.get("EventTime", ""),
                EventSource=item.get("EventSource", ""),
                Username=EmailStr(item.get("Username", "")),
                Resources=item.get("Resources", []),
                CloudTrailEvent=item.get("CloudTrailEvent", ""),
            )
            for event in event_list
            for item in event["Events"]
        ]

        return events

    @staticmethod
    def group_events_by_identity(events: List[EventHistory], region: str) -> bool:
        identity_dict: dict[
            str, List[Optional[dict[str, List[Optional[str]]]]]
        ] = defaultdict(dict)

        user_agents: dict[str, int] = defaultdict(dict)
        for event in events:
            ct_event = json.loads(event.CloudTrailEvent)
            if event.Resources:
                if ct_event["userAgent"] not in user_agents:
                    user_agents[ct_event["userAgent"]] = 0
                user_agents[ct_event["userAgent"]] += 1
                event_dict: Dict[str, List[Optional[str]]] = {}
                if event.EventName not in event_dict:
                    event_dict[event.EventName] = []
                event_dict[event.EventName].append(event.Resources[0].ResourceName)
                if event.Username not in identity_dict:
                    identity_dict[event.Username] = []
                identity_dict[event.Username].append(event_dict)
                
        if not identity_dict:
            logger.error(f"No relevant events found in {region}")
            return False
        df = pd.DataFrame.from_dict(identity_dict, orient="index")

        as_list = df.index.tolist()
        index_list = []
        for _ in as_list:
            user = "".join(random.choices(string.ascii_lowercase, k=5))
            index_list.append(user)
        df.index = index_list

        # Transform the data and append as new columns
        df = pd.concat(
            [
                df[col].apply(lambda x: pd.Series(x, dtype="object"))
                for col in df.columns
            ]
        ).dropna(how="all")
        # Deal with list of values
        for col in df.columns:
            df = df.explode(column=col)

        # Count values
        pd.set_option("display.max_seq_items", None)
        pd.set_option("display.max_colwidth", 500)
        pd.set_option("expand_frame_repr", True)
        pd.options.display.float_format = "{:,.0f}".format
        df = (
            df.groupby(df.index)
            .count()
            .reindex(
                columns=eventActions,
            )
        )

        # Write the dataframe to csv
        df.dropna(how="all", axis=1, inplace=True)
        df.to_csv(f"resources-{region}.csv", encoding="utf-8")
        
        # Write the user agents to a csv
        with open(f'user-agents-{region}.csv', 'w') as csv_file:  
            writer = csv.writer(csv_file)
            writer.writerow(["user_agent", "num_resources"])
            for key, value in user_agents.items():
                writer.writerow([key, value])
        
        return True

    @staticmethod
    def handle(region):
        event_history = EventHandler.create_events_object(region)
        if not event_history:
            logger.info(f"No Event History found for {region}")
            return False
        grouped_events: bool = EventHandler.group_events_by_identity(event_history, region)
        return grouped_events


def run() -> Dict[str, Any]:
    region = EventHandler.process_inputs()
    if region not in Regions:
        print("invalid region!")
        return {
            "body": False,
        }
    
    if region == "all":
        for r in Regions[1:]:
            try:
                response = EventHandler.handle(r)
            except Exception as e:
                logger.error(f"Error getting event in region {r}.\n{e}")
    else:
        response = EventHandler.handle(region)

    return {
        "body": response,
    }


if __name__ == "__main__":
    run()
