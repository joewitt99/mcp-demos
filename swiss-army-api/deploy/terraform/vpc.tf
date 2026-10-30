################################################################################
# Optional demo VPC.
#
# When var.create_vpc = true, provisions a minimal stack good enough to run the
# Fargate task with internet egress and an internet-facing ALB:
#   - 1 VPC          (var.new_vpc_cidr)
#   - 1 IGW
#   - 2 public /20 subnets in distinct AZs (auto-assign public IPs)
#   - 1 route table with a default route to the IGW
#   - 2 RT associations
#
# Tasks share the public subnets (no NAT). Outbound traffic to Docker Hub +
# Okta works because subnets auto-assign public IPs and tasks are configured
# with assign_public_ip = true. NOT for production — tighten by adding a NAT
# and private subnets, or bring your own VPC and set create_vpc=false.
################################################################################

locals {
  # Only call DescribeAvailabilityZones when we actually need to (creating a
  # VPC AND the operator didn't supply explicit AZ names). Some restricted
  # deploy roles deny this read.
  query_azs = var.create_vpc && length(var.availability_zones) == 0
}

data "aws_availability_zones" "available" {
  count = local.query_azs ? 1 : 0
  state = "available"
}

resource "aws_vpc" "this" {
  count                = var.create_vpc ? 1 : 0
  cidr_block           = var.new_vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true
  tags                 = merge(local.tags, { Name = "${local.name}-vpc" })
}

resource "aws_internet_gateway" "this" {
  count  = var.create_vpc ? 1 : 0
  vpc_id = aws_vpc.this[0].id
  tags   = merge(local.tags, { Name = "${local.name}-igw" })
}

resource "aws_subnet" "public" {
  count                   = var.create_vpc ? 2 : 0
  vpc_id                  = aws_vpc.this[0].id
  cidr_block              = cidrsubnet(var.new_vpc_cidr, 4, count.index)
  availability_zone       = local.query_azs ? data.aws_availability_zones.available[0].names[count.index] : var.availability_zones[count.index]
  map_public_ip_on_launch = true
  tags                    = merge(local.tags, { Name = "${local.name}-public-${count.index}" })
}

resource "aws_route_table" "public" {
  count  = var.create_vpc ? 1 : 0
  vpc_id = aws_vpc.this[0].id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.this[0].id
  }

  tags = merge(local.tags, { Name = "${local.name}-public-rt" })
}

resource "aws_route_table_association" "public" {
  count          = var.create_vpc ? 2 : 0
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public[0].id
}
