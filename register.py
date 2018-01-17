#!/usr/bin/env python

import argparse
import logging
import os
import boto3
from time import sleep


region_name = os.environ.get("AWS_REGION", "us-west-2")
aws = boto3.session.Session(region_name=region_name)


def get_ecs_service_ips(service_name, cluster="default", private=True):
    """
    Get the IP addresses of the currently running tasks of the service.
    :return None, if no tasks are running, or [list of IP addresses]
    """
    client = aws.client("ecs")

    response = client.list_tasks(
        cluster=cluster, serviceName=service_name,
        desiredStatus="RUNNING")
    if response["ResponseMetadata"]["HTTPStatusCode"] != 200:
        raise Exception(response["ResponseMetadata"])

    response = client.describe_tasks(
        cluster=cluster, tasks=response["taskArns"])
    if response["ResponseMetadata"]["HTTPStatusCode"] != 200:
        raise Exception(response["ResponseMetadata"])

    instance_arns = []
    for task in response["tasks"]:
        if task["lastStatus"] == "RUNNING":
            instance_arns.append(task["containerInstanceArn"])

    response = client.describe_container_instances(
        cluster=cluster, containerInstances=instance_arns)
    if response["ResponseMetadata"]["HTTPStatusCode"] != 200:
        raise Exception(response["ResponseMetadata"])

    instance_ids = [i["ec2InstanceId"] for i in response["containerInstances"]]

    return get_instances_ips(instance_ids, private)


def get_autoscaling_ips(group_name, private=True):
    """
    Get the IP addresses of the currently running instances in an auto scaling
    group
    """
    autoscale = aws.client('autoscaling')

    response = autoscale.describe_auto_scaling_groups(
        AutoScalingGroupNames=[group_name])
    if response["ResponseMetadata"]["HTTPStatusCode"] != 200:
        raise Exception(response["ResponseMetadata"])

    group = response['AutoScalingGroups'][0]
    instance_ids = [i["InstanceId"] for i in group["Instances"]]

    return get_instances_ips(instance_ids, private)


def get_instances_ips(instance_ids, private=True):
    """
    Get ips of instances from their ids
    """
    ec2 = aws.resource("ec2")

    ipaddresses = []
    instances = ec2.instances.filter(InstanceIds=instance_ids)
    for inst in instances:
        if private:
            if inst.private_ip_address is not None:
                ipaddresses.append(inst.private_ip_address)
        elif inst.public_ip_address is not None:
            ipaddresses.append(inst.public_ip_address)
    return ipaddresses


def register(fqdn, ips, private=True, dryrun=False):
    """
    register creates `A` records for a given a service, and
    (running) container, by using find in either private or public DNS entries
    in Route 53
    """
    route53 = aws.client("route53")

    zone_name = ".".join(fqdn.split(".")[1:])
    zone = get_hosted_zone(zone_name, private)

    if zone is None:
        raise Exception("No hosted zone for {0}, searched: {1}".format(
            fqdn, zone_name
        ))

    response = route53.list_resource_record_sets(
        HostedZoneId=zone["Id"],
        StartRecordName=fqdn,
        StartRecordType="A"
    )
    if response["ResponseMetadata"]["HTTPStatusCode"] != 200:
        raise Exception(response["ResponseMetadata"])

    existing = []
    for recordset in response["ResourceRecordSets"]:
        if recordset["Name"] == fqdn:  # should hit on first
            for rs in recordset["ResourceRecords"]:
                existing.append(rs["Value"])
            break

    if set(existing) != set(ips):  # set resource records
        logging.info("Register A {0} pointing at {1}".format(fqdn, ips))
        if not dryrun:
            response = route53.change_resource_record_sets(
                HostedZoneId=zone["Id"],
                ChangeBatch={
                    "Comment": "updated by ecs (register) container",
                    "Changes": [
                        {
                            "Action": "UPSERT",
                            "ResourceRecordSet": {
                                "Name": fqdn,
                                "ResourceRecords": [{"Value": a} for a in ips],
                                "TTL": 20,
                                "Type": "A"
                            }
                        }
                    ]
                }
            )

            if response["ResponseMetadata"]["HTTPStatusCode"] != 200:
                raise Exception(response["ResponseMetadata"])

            return True


def register_cname(fqdn, cname, private=True, dryrun=False):
    """
    Register cname pointing to fqdn in region. Private means the hosted
    zone should be private.
    """
    route53 = aws.client("route53")

    zone_name = ".".join(fqdn.split(".")[1:])
    zone = get_hosted_zone(zone_name, private)

    if zone is None:
        raise Exception("No hosted zone for {0}, searched: {1}".format(
            fqdn, zone_name))

    response = route53.list_resource_record_sets(
        HostedZoneId=zone["Id"], StartRecordName=cname,
        StartRecordType="CNAME")
    if response["ResponseMetadata"]["HTTPStatusCode"] != 200:
        raise Exception(response["ResponseMetadata"])

    for recordset in response["ResourceRecordSets"]:
        if recordset["Name"] == cname:  # should hit on first iteration
            for rs in recordset["ResourceRecords"]:
                if rs["Value"] == fqdn:
                    return None  # CNAME is already in desired state
            break

    logging.info("Register CNAME {0} pointing at {1}".format(cname, fqdn))
    if not dryrun:
        response = route53.change_resource_record_sets(
            HostedZoneId=zone["Id"],
            ChangeBatch={
                "Comment": "Managed by ecs register script",
                "Changes": [
                    {
                        "Action": "UPSERT",
                        "ResourceRecordSet": {
                            "Name": cname,
                            "ResourceRecords": [{"Value": fqdn}],
                            "TTL": 20,
                            "Type": "CNAME"
                        }
                    }
                ]
            }
        )
        if response["ResponseMetadata"]["HTTPStatusCode"] != 200:
            raise Exception(response["ResponseMetadata"])

    return True


def get_hosted_zone(zone_name, private=True):
    """
    Get a hosted zone by name and if it"s private or not
    """
    route53 = aws.client("route53")
    response = route53.list_hosted_zones(MaxItems="100")
    if response["ResponseMetadata"]["HTTPStatusCode"] != 200:
        raise ValueError(response["ResponseMetadata"])

    for zone in response["HostedZones"]:
        if zone["Name"] != zone_name:
            continue
        elif zone["Config"]["PrivateZone"] == private:
            return zone


def update_dns(target, fqdn, cname=None, public=False, dryrun=False):
    """
    Point the fqdn to the ips of the provided resource.
    """

    # Make sure fqdn is a proper FQDN
    if not fqdn.endswith("."):
        fqdn += "."

    # Make sure cname is a proper FQDN
    if cname and not cname.endswith("."):
        cname += "."

    data = target.split(":")
    if data[0] == "ecs":
        func = get_ecs_service_ips
        kwargs = {
            "cluster": data[1],
            "service_name": data[2]
        }
    elif data[0] == "asg":
        func = get_autoscaling_ips
        kwargs = {
            "group_name": data[1]
        }
    else:
        raise Exception("Unrecognised resource type {}".format(data[0]))

    private_ips = func(private=True, **kwargs)
    register(fqdn, private_ips, private=True, dryrun=dryrun)

    if cname:
        register_cname(fqdn, cname, dryrun=dryrun)

    if public:
        public_ips = func(private=False, **kwargs)
        register(fqdn, public_ips, private=False, dryrun=dryrun)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--target", dest="target", required=True,
        help="the resource to register. e.g. ecs:ClusterName:ServiceName "
             "or asg:AutoscalingGroup")

    parser.add_argument(
        "--fqdn", dest="fqdn", required=True,
        help="the FQDN for the A record")
    parser.add_argument(
        "--cname", dest="cname", default="",
        help="also create a cname pointing to the FQDN")
    parser.add_argument(
        "--public", action="store_true", default=False,
        help="also create a public FQDN with same name as the private")
    parser.add_argument(
        "--dryrun", action="store_true", default=False,
        help="test with a dryrun")

    parser.add_argument(
        "-r", "--rerun", action="store_true", default=False,
        help="run again after a 60 second pause")

    args = parser.parse_args()

    logging.getLogger().setLevel(logging.INFO)

    kwargs = {
        "target": args.target,
        "fqdn": args.fqdn,
        "cname": args.cname,
        "public": args.public,
        "dryrun": args.dryrun
    }
    update_dns(**kwargs)
    if args.rerun:
        sleep(60)
        update_dns(**kwargs)


if __name__ == "__main__":
    main()
