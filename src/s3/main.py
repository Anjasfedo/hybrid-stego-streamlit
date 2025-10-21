from s3.main import s3, S3_BUCKET, PRESIGN_TTL
from botocore.exceptions import ClientError
import os
import tempfile
from uuid import uuid4
import re
import os
import boto3
from botocore.config import Config
from dotenv import load_dotenv

load_dotenv()

# ----- S3 / MinIO config -----
S3_ENDPOINT = os.getenv("S3_ENDPOINT")
S3_ACCESS_KEY = os.getenv("S3_ACCESS_KEY")
S3_SECRET_KEY = os.getenv("S3_SECRET_KEY")
S3_BUCKET = os.getenv("S3_BUCKET", "fastapi")
PRESIGN_TTL = int(os.getenv("S3_PRESIGN_TTL", "3600"))

s3 = boto3.client(
    "s3",
    endpoint_url=S3_ENDPOINT,
    aws_access_key_id=S3_ACCESS_KEY,
    aws_secret_access_key=S3_SECRET_KEY,
    config=Config(signature_version="s3v4", s3={"addressing_style": "path"}),
)


def safe_name(name: str) -> str:
    base = name.rsplit("/", 1)[-1]
    return re.sub(r"[^A-Za-z0-9._-]", "_", base) or "file"


def ensure_bucket(bucket: str):
    """Create bucket if it doesn't exist (idempotent)."""
    try:
        s3.head_bucket(Bucket=bucket)
    except ClientError as e:
        code = int(e.response.get("ResponseMetadata",
                   {}).get("HTTPStatusCode", 0))
        if code == 404:
            s3.create_bucket(Bucket=bucket)
        elif code == 301:
            # Wrong region or not found; try create
            s3.create_bucket(Bucket=bucket)
        else:
            raise


def upload_bytes_and_get_key(prefix: str, filename: str, data: bytes, content_type: str):
    ensure_bucket(S3_BUCKET)
    key = f"{prefix}/{uuid4().hex}/{filename}"
    s3.put_object(Bucket=S3_BUCKET, Key=key,
                  Body=data, ContentType=content_type)
    return key


def presign_get_url(key: str, ttl: int = PRESIGN_TTL) -> str:
    return s3.generate_presigned_url(
        ClientMethod="get_object",
        Params={"Bucket": S3_BUCKET, "Key": key},
        ExpiresIn=ttl,
    )


def download_to_tmp(bucket: str, key: str) -> str:
    suffix = os.path.splitext(key)[1] or ".png"
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
    tmp.close()
    s3.download_file(bucket, key, tmp.name)
    return tmp.name
