"""Every test runs against a mocked AWS (moto), so no real account is touched."""
import os

os.environ.update(
    AWS_ACCESS_KEY_ID="testing",
    AWS_SECRET_ACCESS_KEY="testing",
    AWS_SESSION_TOKEN="testing",
    AWS_DEFAULT_REGION="us-east-1",
    AWS_EC2_METADATA_DISABLED="true",
    SECRET_KEY="test-secret-key",
    SCANNER_PASSWORD="test-password",
)

import boto3  # noqa: E402
import pytest  # noqa: E402
from moto import mock_aws  # noqa: E402


@pytest.fixture
def session():
    """A boto3 session whose AWS calls all go to moto."""
    with mock_aws():
        yield boto3.Session(region_name="us-east-1")


def an_image_id(session) -> str:
    return session.client("ec2").describe_images()["Images"][0]["ImageId"]


def launch_instance(session, tags=None) -> str:
    kwargs = {}
    if tags is not None:
        kwargs["TagSpecifications"] = [
            {"ResourceType": "instance", "Tags": [{"Key": k, "Value": v} for k, v in tags.items()]}
        ]
    result = session.client("ec2").run_instances(ImageId=an_image_id(session), MinCount=1, MaxCount=1, **kwargs)
    return result["Instances"][0]["InstanceId"]
