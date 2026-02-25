#!/usr/bin/env bash
set -euo pipefail

slugify() {
  local s="$1"
  s="$(echo "$s" | tr '[:upper:]' '[:lower:]' | sed -E 's/[^a-z0-9]+/-/g; s/^-+//; s/-+$//; s/-+/-/g')"
  if [[ -z "$s" ]]; then
    s="openclaw-bot"
  fi
  echo "$s" | cut -c1-32
}

check_aws_cli() {
  if ! command -v aws &>/dev/null; then
    echo -e "\033[1;31m✗ AWS CLI not found\033[0m"
    echo -e "  \033[36mbrew install awscli\033[0m"
    exit 1
  fi

  if ! aws sts get-caller-identity &>/dev/null; then
    echo -e "\033[1;31m✗ Not logged into AWS\033[0m"
    echo -e "  Run: \033[36maws login\033[0m"
    exit 1
  fi
}

usage() {
  cat <<USAGE
Usage:
  ./deploy_openclaw_ec2.sh [bot-name]
  ./deploy_openclaw_ec2.sh --bot-name NAME [--network-mode ipv4|dualstack|ipv6-only] [--instance-type TYPE] [--ssh-cidr-v4 CIDR] [--ssh-cidr-v6 CIDR] [--region REGION] [--elastic-ip] [--yes]

Options:
  -b, --bot-name NAME        Bot name (EC2 Name tag)
  -m, --network-mode MODE    ipv4 | dualstack | ipv6-only
  -t, --instance-type TYPE   EC2 type (interactive prompt if omitted)
      --ssh-cidr-v4 CIDR     SSH IPv4 CIDR (default: 0.0.0.0/0)
      --ssh-cidr-v6 CIDR     SSH IPv6 CIDR (default: ::/0)
  -r, --region REGION        AWS region (default: AWS config)
  -e, --elastic-ip           Allocate and attach a static Elastic IP (free while attached to running instance)
  -y, --yes                  Non-interactive mode (requires bot name + network mode; defaults type to t3.small)
  -h, --help                 Show this help
USAGE
}

BOT_NAME_INPUT=""
NETWORK_MODE=""
INSTANCE_TYPE="${INSTANCE_TYPE:-}"
SSH_CIDR_V4="${SSH_CIDR_V4:-0.0.0.0/0}"
SSH_CIDR_V6="${SSH_CIDR_V6:-::/0}"
REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-}}"
ELASTIC_IP=0
NON_INTERACTIVE=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    -b|--bot-name)
      BOT_NAME_INPUT="$2"
      shift 2
      ;;
    -m|--network-mode)
      NETWORK_MODE="$2"
      shift 2
      ;;
    -t|--instance-type)
      INSTANCE_TYPE="$2"
      shift 2
      ;;
    --ssh-cidr-v4)
      SSH_CIDR_V4="$2"
      shift 2
      ;;
    --ssh-cidr-v6)
      SSH_CIDR_V6="$2"
      shift 2
      ;;
    -r|--region)
      REGION="$2"
      shift 2
      ;;
    -e|--elastic-ip)
      ELASTIC_IP=1
      shift
      ;;
    -y|--yes)
      NON_INTERACTIVE=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --)
      shift
      break
      ;;
    -*)
      echo "Unknown option: $1" >&2
      usage
      exit 1
      ;;
    *)
      if [[ -z "$BOT_NAME_INPUT" ]]; then
        BOT_NAME_INPUT="$1"
        shift
      else
        echo "Unexpected positional argument: $1" >&2
        usage
        exit 1
      fi
      ;;
  esac
done

# Check AWS CLI installation and credentials BEFORE any user prompts
check_aws_cli

# If region not set via env var, try to get it from AWS config now that we know aws is working
if [[ -z "$REGION" || "$REGION" == "None" ]]; then
  REGION="$(aws configure get region 2>/dev/null || true)"
fi

if [[ -z "$BOT_NAME_INPUT" ]]; then
  if [[ "$NON_INTERACTIVE" -eq 1 ]]; then
    echo "--bot-name is required with --yes" >&2
    exit 1
  fi
  read -r -p "Bot name (used for EC2 Name tag): " BOT_NAME_INPUT
fi
if [[ -z "$BOT_NAME_INPUT" ]]; then
  echo "Bot name is required." >&2
  exit 1
fi

if [[ -z "$NETWORK_MODE" ]]; then
  if [[ "$NON_INTERACTIVE" -eq 1 ]]; then
    echo "--network-mode is required with --yes" >&2
    exit 1
  fi
  cat <<CHOICES
Select network mode:
  1) ipv4      (public IPv4 SSH, simplest)
  2) dualstack (public IPv4 + IPv6)
  3) ipv6-only (public IPv6 only, no public IPv4 hourly charge)
CHOICES
  read -r -p "Enter choice [1/2/3] (default 1): " NET_CHOICE
  case "${NET_CHOICE:-1}" in
    1) NETWORK_MODE="ipv4" ;;
    2) NETWORK_MODE="dualstack" ;;
    3) NETWORK_MODE="ipv6-only" ;;
    *)
      echo "Invalid network choice." >&2
      exit 1
      ;;
  esac
fi

case "$NETWORK_MODE" in
  ipv4|dualstack|ipv6-only) ;;
  *)
    echo "Invalid --network-mode '$NETWORK_MODE'. Use ipv4, dualstack, or ipv6-only." >&2
    exit 1
    ;;
esac

if [[ -z "$INSTANCE_TYPE" ]]; then
  if [[ "$NON_INTERACTIVE" -eq 1 ]]; then
    INSTANCE_TYPE="t3.small"
  else
    cat <<'CHOICES'
Select instance tier (t3 - burstable, general purpose):
  1) t3.nano    (2 vCPU, 0.5 GiB,   ~$4/month)
  2) t3.micro   (2 vCPU, 1 GiB,     ~$8/month)
  3) t3.small   (2 vCPU, 2 GiB,     ~$15/month) [default]
  4) t3.medium  (2 vCPU, 4 GiB,     ~$30/month)
  5) t3.large   (2 vCPU, 8 GiB,     ~$60/month)
  6) t3.xlarge  (4 vCPU, 16 GiB,    ~$120/month)

Select instance tier (m5 - consistent, general purpose):
  7) m5.large   (2 vCPU, 8 GiB,     ~$70/month)
  8) m5.xlarge  (4 vCPU, 16 GiB,    ~$140/month)
  9) m5.2xlarge (8 vCPU, 32 GiB,    ~$280/month)

Select instance tier (c5 - compute optimized):
 10) c5.large   (2 vCPU, 4 GiB,     ~$65/month)
 11) c5.xlarge  (4 vCPU, 8 GiB,     ~$130/month)
 12) c5.2xlarge (8 vCPU, 16 GiB,    ~$260/month)

  0) custom     (enter any instance type)
CHOICES
    read -r -p "Enter choice [0-12] (default 3): " SIZE_CHOICE
    case "${SIZE_CHOICE:-3}" in
      1) INSTANCE_TYPE="t3.nano" ;;
      2) INSTANCE_TYPE="t3.micro" ;;
      3) INSTANCE_TYPE="t3.small" ;;
      4) INSTANCE_TYPE="t3.medium" ;;
      5) INSTANCE_TYPE="t3.large" ;;
      6) INSTANCE_TYPE="t3.xlarge" ;;
      7) INSTANCE_TYPE="m5.large" ;;
      8) INSTANCE_TYPE="m5.xlarge" ;;
      9) INSTANCE_TYPE="m5.2xlarge" ;;
      10) INSTANCE_TYPE="c5.large" ;;
      11) INSTANCE_TYPE="c5.xlarge" ;;
      12) INSTANCE_TYPE="c5.2xlarge" ;;
      0)
        read -r -p "Enter instance type (e.g. t3.2xlarge, c5.4xlarge): " INSTANCE_TYPE
        if [[ -z "$INSTANCE_TYPE" ]]; then
          echo "Instance type cannot be empty." >&2
          exit 1
        fi
        ;;
      *)
        echo "Invalid instance choice." >&2
        exit 1
        ;;
    esac
  fi
fi
echo "Using instance type: ${INSTANCE_TYPE}"

if [[ -z "$REGION" || "$REGION" == "None" ]]; then
  echo "AWS region is not configured. Set AWS_REGION or run: aws configure" >&2
  exit 1
fi

BOT_SLUG="$(slugify "$BOT_NAME_INPUT")"
TIMESTAMP="$(date +%Y%m%d%H%M%S)"

ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text)"
echo "Using AWS account ${ACCOUNT_ID} in region ${REGION}"
echo "Deploying bot '${BOT_NAME_INPUT}' with instance '${INSTANCE_TYPE}' and network '${NETWORK_MODE}'"

AZ="$(aws ec2 describe-availability-zones --region "$REGION" --filters Name=state,Values=available --query 'AvailabilityZones[0].ZoneName' --output text)"
if [[ -z "$AZ" || "$AZ" == "None" ]]; then
  echo "Failed to discover an availability zone in region ${REGION}." >&2
  exit 1
fi

VPC_ID="$(aws ec2 describe-vpcs --region "$REGION" --filters Name=isDefault,Values=true --query 'Vpcs[0].VpcId' --output text)"
if [[ -z "$VPC_ID" || "$VPC_ID" == "None" ]]; then
  echo "No default VPC found in ${REGION}. Create one or edit this script to target a custom VPC." >&2
  exit 1
fi

SUBNET_ID="$(aws ec2 describe-subnets --region "$REGION" --filters Name=vpc-id,Values="$VPC_ID" Name=availability-zone,Values="$AZ" --query 'Subnets[0].SubnetId' --output text)"
if [[ -z "$SUBNET_ID" || "$SUBNET_ID" == "None" ]]; then
  SUBNET_ID="$(aws ec2 describe-subnets --region "$REGION" --filters Name=vpc-id,Values="$VPC_ID" --query 'Subnets[0].SubnetId' --output text)"
fi
if [[ -z "$SUBNET_ID" || "$SUBNET_ID" == "None" ]]; then
  echo "No subnet found in VPC ${VPC_ID}." >&2
  exit 1
fi

NEEDS_IPV6=0
if [[ "$NETWORK_MODE" == "dualstack" || "$NETWORK_MODE" == "ipv6-only" ]]; then
  NEEDS_IPV6=1
fi

if [[ "$NEEDS_IPV6" -eq 1 ]]; then
  VPC_IPV6_CIDR="$(aws ec2 describe-vpcs --region "$REGION" --vpc-ids "$VPC_ID" --query 'Vpcs[0].Ipv6CidrBlockAssociationSet[?Ipv6CidrBlockState.State==`associated`].Ipv6CidrBlock | [0]' --output text)"
  if [[ -z "$VPC_IPV6_CIDR" || "$VPC_IPV6_CIDR" == "None" ]]; then
    echo "Associating IPv6 CIDR to VPC ${VPC_ID}"
    ASSOC_ID="$(aws ec2 associate-vpc-cidr-block --region "$REGION" --vpc-id "$VPC_ID" --amazon-provided-ipv6-cidr-block --query 'Ipv6CidrBlockAssociation.AssociationId' --output text)"
    for _ in {1..30}; do
      STATE="$(aws ec2 describe-vpcs --region "$REGION" --vpc-ids "$VPC_ID" --query "Vpcs[0].Ipv6CidrBlockAssociationSet[?AssociationId=='${ASSOC_ID}'].Ipv6CidrBlockState.State | [0]" --output text)"
      if [[ "$STATE" == "associated" ]]; then
        break
      fi
      sleep 3
    done
    VPC_IPV6_CIDR="$(aws ec2 describe-vpcs --region "$REGION" --vpc-ids "$VPC_ID" --query 'Vpcs[0].Ipv6CidrBlockAssociationSet[?Ipv6CidrBlockState.State==`associated`].Ipv6CidrBlock | [0]' --output text)"
  fi

  if [[ -z "$VPC_IPV6_CIDR" || "$VPC_IPV6_CIDR" == "None" ]]; then
    echo "Unable to ensure IPv6 CIDR on VPC ${VPC_ID}." >&2
    exit 1
  fi

  SUBNET_IPV6_CIDR="$(aws ec2 describe-subnets --region "$REGION" --subnet-ids "$SUBNET_ID" --query 'Subnets[0].Ipv6CidrBlockAssociationSet[?Ipv6CidrBlockState.State==`associated`].Ipv6CidrBlock | [0]' --output text)"
  if [[ -z "$SUBNET_IPV6_CIDR" || "$SUBNET_IPV6_CIDR" == "None" ]]; then
    USED_SUBNET_CIDRS="$(aws ec2 describe-subnets --region "$REGION" --filters Name=vpc-id,Values="$VPC_ID" --query 'Subnets[].Ipv6CidrBlockAssociationSet[?Ipv6CidrBlockState.State==`associated`].Ipv6CidrBlock' --output text | tr '\t' '\n' | sed '/^$/d')"
    CANDIDATE="$(python3 - <<PY
import ipaddress
vpc = ipaddress.IPv6Network("$VPC_IPV6_CIDR", strict=False)
used = {line.strip() for line in """$USED_SUBNET_CIDRS""".splitlines() if line.strip() and line.strip() != "None"}
for s in vpc.subnets(new_prefix=64):
    cidr = str(s)
    if cidr not in used:
        print(cidr)
        break
PY
)"
    if [[ -z "$CANDIDATE" ]]; then
      echo "No free /64 IPv6 subnet range available in VPC ${VPC_ID}." >&2
      exit 1
    fi
    aws ec2 associate-subnet-cidr-block --region "$REGION" --subnet-id "$SUBNET_ID" --ipv6-cidr-block "$CANDIDATE" >/dev/null
    for _ in {1..20}; do
      SUBNET_IPV6_CIDR="$(aws ec2 describe-subnets --region "$REGION" --subnet-ids "$SUBNET_ID" --query 'Subnets[0].Ipv6CidrBlockAssociationSet[?Ipv6CidrBlockState.State==`associated`].Ipv6CidrBlock | [0]' --output text)"
      if [[ "$SUBNET_IPV6_CIDR" != "None" && -n "$SUBNET_IPV6_CIDR" ]]; then
        break
      fi
      sleep 2
    done
  fi

  IGW_ID="$(aws ec2 describe-internet-gateways --region "$REGION" --filters Name=attachment.vpc-id,Values="$VPC_ID" --query 'InternetGateways[0].InternetGatewayId' --output text)"
  if [[ -z "$IGW_ID" || "$IGW_ID" == "None" ]]; then
    echo "No Internet Gateway attached to VPC ${VPC_ID}, required for IPv6 internet routing." >&2
    exit 1
  fi

  ROUTE_TABLE_ID="$(aws ec2 describe-route-tables --region "$REGION" --filters Name=association.subnet-id,Values="$SUBNET_ID" --query 'RouteTables[0].RouteTableId' --output text)"
  if [[ -z "$ROUTE_TABLE_ID" || "$ROUTE_TABLE_ID" == "None" ]]; then
    ROUTE_TABLE_ID="$(aws ec2 describe-route-tables --region "$REGION" --filters Name=vpc-id,Values="$VPC_ID" Name=association.main,Values=true --query 'RouteTables[0].RouteTableId' --output text)"
  fi
  if [[ -z "$ROUTE_TABLE_ID" || "$ROUTE_TABLE_ID" == "None" ]]; then
    echo "Unable to find route table for subnet ${SUBNET_ID}." >&2
    exit 1
  fi

  aws ec2 create-route --region "$REGION" --route-table-id "$ROUTE_TABLE_ID" --destination-ipv6-cidr-block ::/0 --gateway-id "$IGW_ID" >/dev/null 2>&1 || true
fi

SG_NAME="${BOT_SLUG}-sg"
SG_ID="$(aws ec2 describe-security-groups --region "$REGION" --filters Name=vpc-id,Values="$VPC_ID" Name=group-name,Values="$SG_NAME" --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null || true)"
if [[ -z "$SG_ID" || "$SG_ID" == "None" ]]; then
  SG_ID="$(aws ec2 create-security-group --region "$REGION" --group-name "$SG_NAME" --description "OpenClaw SSH access for ${BOT_NAME_INPUT}" --vpc-id "$VPC_ID" --query GroupId --output text)"
  aws ec2 create-tags --region "$REGION" --resources "$SG_ID" --tags Key=Name,Value="$SG_NAME" Key=Project,Value=OpenClaw >/dev/null
fi

if [[ "$NETWORK_MODE" == "ipv4" || "$NETWORK_MODE" == "dualstack" ]]; then
  aws ec2 authorize-security-group-ingress \
    --region "$REGION" \
    --group-id "$SG_ID" \
    --ip-permissions "[{\"IpProtocol\":\"tcp\",\"FromPort\":22,\"ToPort\":22,\"IpRanges\":[{\"CidrIp\":\"${SSH_CIDR_V4}\",\"Description\":\"SSH IPv4\"}]}]" \
    >/dev/null 2>&1 || true
fi

if [[ "$NETWORK_MODE" == "dualstack" || "$NETWORK_MODE" == "ipv6-only" ]]; then
  aws ec2 authorize-security-group-ingress \
    --region "$REGION" \
    --group-id "$SG_ID" \
    --ip-permissions "[{\"IpProtocol\":\"tcp\",\"FromPort\":22,\"ToPort\":22,\"Ipv6Ranges\":[{\"CidrIpv6\":\"${SSH_CIDR_V6}\",\"Description\":\"SSH IPv6\"}]}]" \
    >/dev/null 2>&1 || true
fi

# HTTPS (port 443) - open to the world
if [[ "$NETWORK_MODE" == "ipv4" || "$NETWORK_MODE" == "dualstack" ]]; then
  aws ec2 authorize-security-group-ingress \
    --region "$REGION" \
    --group-id "$SG_ID" \
    --ip-permissions "[{\"IpProtocol\":\"tcp\",\"FromPort\":443,\"ToPort\":443,\"IpRanges\":[{\"CidrIp\":\"0.0.0.0/0\",\"Description\":\"HTTPS IPv4\"}]}]" \
    >/dev/null 2>&1 || true
fi

if [[ "$NETWORK_MODE" == "dualstack" || "$NETWORK_MODE" == "ipv6-only" ]]; then
  aws ec2 authorize-security-group-ingress \
    --region "$REGION" \
    --group-id "$SG_ID" \
    --ip-permissions "[{\"IpProtocol\":\"tcp\",\"FromPort\":443,\"ToPort\":443,\"Ipv6Ranges\":[{\"CidrIpv6\":\"::/0\",\"Description\":\"HTTPS IPv6\"}]}]" \
    >/dev/null 2>&1 || true
fi

ROLE_NAME="openclaw-ec2-role"
PROFILE_NAME="openclaw-ec2-profile"

if ! aws iam get-role --role-name "$ROLE_NAME" >/dev/null 2>&1; then
  cat > /tmp/openclaw-trust-policy.json <<'JSON'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {"Service": "ec2.amazonaws.com"},
      "Action": "sts:AssumeRole"
    }
  ]
}
JSON
  aws iam create-role --role-name "$ROLE_NAME" --assume-role-policy-document file:///tmp/openclaw-trust-policy.json >/dev/null
fi

aws iam attach-role-policy --role-name "$ROLE_NAME" --policy-arn arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore >/dev/null

if ! aws iam get-instance-profile --instance-profile-name "$PROFILE_NAME" >/dev/null 2>&1; then
  aws iam create-instance-profile --instance-profile-name "$PROFILE_NAME" >/dev/null
fi

if ! aws iam get-instance-profile --instance-profile-name "$PROFILE_NAME" --query "InstanceProfile.Roles[?RoleName=='$ROLE_NAME'].RoleName" --output text | grep -q "$ROLE_NAME"; then
  aws iam add-role-to-instance-profile --instance-profile-name "$PROFILE_NAME" --role-name "$ROLE_NAME" >/dev/null || true
fi

sleep 10

AMI_ID="$(aws ssm get-parameter --region "$REGION" --name /aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64 --query Parameter.Value --output text)"
if [[ -z "$AMI_ID" || "$AMI_ID" == "None" ]]; then
  echo "Failed to resolve Amazon Linux 2023 AMI from SSM." >&2
  exit 1
fi

KEY_NAME="${BOT_SLUG}-${TIMESTAMP}"
KEY_PATH="$HOME/.ssh/${KEY_NAME}.pem"
mkdir -p "$HOME/.ssh"

aws ec2 create-key-pair --region "$REGION" --key-name "$KEY_NAME" --key-type rsa --key-format pem --query KeyMaterial --output text > "$KEY_PATH"
chmod 400 "$KEY_PATH"

USER_DATA_FILE="/tmp/openclaw-user-data-${TIMESTAMP}.sh"
cat > "$USER_DATA_FILE" <<'USERDATA'
#!/bin/bash
set -euxo pipefail

exec > >(tee /var/log/openclaw-bootstrap.log | logger -t openclaw-bootstrap -s 2>/dev/console) 2>&1

export HOME=/root
dnf update -y || true

grep -q 'npm-global/bin' /home/ec2-user/.bashrc 2>/dev/null || \
  echo 'export PATH="$HOME/.npm-global/bin:$PATH"' >> /home/ec2-user/.bashrc
chown ec2-user:ec2-user /home/ec2-user/.bashrc

su - ec2-user -c 'export HOME=/home/ec2-user; export OPENCLAW_NO_PROMPT=1 OPENCLAW_NO_ONBOARD=1 OPENCLAW_USE_GUM=0; curl -fsSL https://openclaw.ai/install.sh | bash -s -- --no-prompt --no-onboard'

if [[ -x /home/ec2-user/.npm-global/bin/openclaw ]]; then
  ln -sf /home/ec2-user/.npm-global/bin/openclaw /usr/local/bin/openclaw
fi

openclaw --version || true
USERDATA

RUN_ARGS=(
  --region "$REGION"
  --image-id "$AMI_ID"
  --instance-type "$INSTANCE_TYPE"
  --iam-instance-profile Name="$PROFILE_NAME"
  --key-name "$KEY_NAME"
  --security-group-ids "$SG_ID"
  --subnet-id "$SUBNET_ID"
  --user-data "file://${USER_DATA_FILE}"
  --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=${BOT_NAME_INPUT}},{Key=Project,Value=OpenClaw},{Key=BotName,Value=${BOT_NAME_INPUT}},{Key=NetworkMode,Value=${NETWORK_MODE}}]"
  --query 'Instances[0].InstanceId'
  --output text
)

if [[ "$NETWORK_MODE" == "ipv4" ]]; then
  RUN_ARGS+=(--associate-public-ip-address)
elif [[ "$NETWORK_MODE" == "dualstack" ]]; then
  RUN_ARGS+=(--associate-public-ip-address --ipv6-address-count 1)
else
  RUN_ARGS+=(--no-associate-public-ip-address --ipv6-address-count 1)
fi

INSTANCE_ID="$(aws ec2 run-instances "${RUN_ARGS[@]}")"

aws ec2 wait instance-running --region "$REGION" --instance-ids "$INSTANCE_ID"
aws ec2 wait instance-status-ok --region "$REGION" --instance-ids "$INSTANCE_ID"

# Handle Elastic IP allocation if requested
if [[ "$ELASTIC_IP" -eq 1 ]]; then
  echo "Allocating Elastic IP for persistent public IP..."
  EIP_ALLOC="$(aws ec2 allocate-address --domain vpc --region "$REGION" --query AllocationId --output text)"
  echo "Attaching Elastic IP ${EIP_ALLOC} to instance..."
  aws ec2 associate-address --region "$REGION" --instance-id "$INSTANCE_ID" --allocation-id "$EIP_ALLOC" >/dev/null
  echo "Elastic IP attached. This IP will persist across instance stop/start cycles."
  aws ec2 create-tags --region "$REGION" --resources "$EIP_ALLOC" --tags Key=Name,Value="${BOT_NAME_INPUT}-eip" Key=InstanceId,Value="$INSTANCE_ID" >/dev/null
fi

PUBLIC_IP="$(aws ec2 describe-instances --region "$REGION" --instance-ids "$INSTANCE_ID" --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)"
PUBLIC_DNS="$(aws ec2 describe-instances --region "$REGION" --instance-ids "$INSTANCE_ID" --query 'Reservations[0].Instances[0].PublicDnsName' --output text)"
PUBLIC_IPV6="$(aws ec2 describe-instances --region "$REGION" --instance-ids "$INSTANCE_ID" --query 'Reservations[0].Instances[0].NetworkInterfaces[0].Ipv6Addresses[0].Ipv6Address' --output text)"

echo

echo "Deployment complete."
echo "Bot Name Tag : ${BOT_NAME_INPUT}"
echo "Instance ID  : ${INSTANCE_ID}"
echo "Region       : ${REGION}"
echo "Network Mode : ${NETWORK_MODE}"
echo "Public IPv4  : ${PUBLIC_IP}"
echo "Public DNS   : ${PUBLIC_DNS}"
echo "Public IPv6  : ${PUBLIC_IPV6}"
echo "SSH Key      : ${KEY_PATH}"
echo

echo "SSH commands:"
if [[ "$PUBLIC_IP" != "None" && -n "$PUBLIC_IP" ]]; then
  echo "ssh -i ${KEY_PATH} ec2-user@${PUBLIC_IP}"
fi
if [[ "$PUBLIC_IPV6" != "None" && -n "$PUBLIC_IPV6" ]]; then
  echo "ssh -6 -i ${KEY_PATH} ec2-user@[${PUBLIC_IPV6}]"
fi

echo
echo "Bootstrap log after SSH:"
echo "sudo tail -n 200 /var/log/openclaw-bootstrap.log"
