#!/usr/bin/python3

import boto3
import sys
import os
import datetime
import argparse
import json
import ipaddress
import re

# Usage:
#
#   Refer to argparse setup or run:
#       vpc-repr.py -h
#
# Change Log:
#   9/7/2021 Version 1.0, L. Kuhn 
#   9/7/2021 Version 1.0.1, L. Kuhn
#     - fixed transit gateway bug (assumed AWS would return nothing for empty id list; returned all)
#   9/8/2021 Version 1.0.2 L. Kuhn
#     - ensure ipv6 cidrs included in vpc peering details
#     - changed warnings from 'something went wrong' to 'this xxx is not yet supported {xxx}'
#   9/14/2021 Version 2.0, L. Kuhn
#     - rewritten for json output and other enhancements (command line options are not backward compatible)
#     - added argparse library for new command line handling
#     - allows specifying AWSCLI profile
#     - saves json and allows sending json to stdout
#     - allows reading from saved json
#     - allows filtering stdout output sections (json or html)
#     - added capability to find ip network matches and highlight in stdout
#   9/15/2021 Version 2.0.1, L. Kuhn
#     - added -split [name|id] option to create multiple reports or json files


def datetime_handler(o):
    # for json.dumps which can't handle serializing these objects
    if isinstance(o, (datetime.datetime, datetime.date)):
        return str(o)


def get_tag_name(tagdict):
    if "Tags" in tagdict:
        for t in range(len(tagdict['Tags'])):
            if tagdict['Tags'][t]['Key'] == "Name":
                return tagdict['Tags'][t]['Value']
    return ""

def main():

    tr = "<tr><td><strong>"
    space = ":</strong><td>"
    spaces = " " * 100
    protocols = {"-1": "All", "1": "ICMP", "6": "TCP", "17": "UDP"}
    button = "<button class='accordion'>"
    div = "</button><div class='sect'>"
    button2 = "<button class='accordion2'>"
    div2 = "</button><div class='sect2'>"
    read_mode = False
    global iptype
    iptype = None
    now = datetime.datetime.now()
    now = now.strftime("%m/%d/%y %I:%M %p")

    ## use argparse library to parse command line options / switches
    argv_epilog = """
    Read Mode:
        . ON when -f filename is specified
        . json is read from filename (not AWS)
        . no interaction with AWS
        . does not save an output json file (ignores any -j output file names)
        . only writes to stdout based on -j or -w switches
    
    Standard Mode:
        . data is collected from AWS:
            . using profile from environment, default or from -profile if specified
            . using region from profile or from -region if specified
            . for all VPCs in region (except default VPC) or only those specified with -vpc-ids
        . complete json from AWS (except ResponseMetadata) is always written to a file
            . describe_vpcs() is used to load the vpc objects into memory
            . each vpc object is augmented with other objects (e.g. "AvailabilityZones":...) using other describe methods to build a larger vpc object
            . output is written to 'vpc-repr.json' unless a filename is specified after -j switch
            . output json is slightly augmented in some cases with a 'Notes' attribute with comments or 'name' data taken from a separate AWS method

    All Modes:
        . -j or -w dictates output format to stdout (-w is assumed if no switch is specified)
            . if -j and -w are not specified, json is written to vpc-repr.json and html is written to stdout
            . if -j and -w are both specified, json is written to filename, if specified, and html is written to stdout
            . if -j alone is specified, json is written to vpc-repr.json or filename specifed, and is written to stdout
        . section switches (e.g. -az, -ci, -do) control stdout output sections only
            . no switches causes ALL sections to be output to stdout
            . one switch will cause the VPC shell and that section only to be output to stdout
            . certain referenced data from other sections may be omitted when that section is not included (e.g. subnet names if -sn section is omitted)
        . to capture section switch limited json to a file, use -j switch and redirect stdout to a file
        . use -ip search switch to look for ip address and network overlaps
        . use -split [name|id] to write multiple output files per VPC versus stdout (JSON or HTML)
            . uses VPC tag name or VPC id as the file name; will overwrite existing files with the same name
            . defaults to name, which will use the name (if available from tags) or use id
            . split json files can be read back into application using -f filename option
    	. defaults to name, which will use the name (if available from tags) or use id
        . use -verbose switch for more info on -ip switch and command line examples
    """
    argv_verbose = """
    IP Search Switch:
        . read data from AWS or json file
        . processes all other command line options
        . -ip address or -ip network can be used (e.g. 10.10.10.10 or 10.10.10.0/24)
        . ipv4 and ipv6 are supported; these json keys are inspected:
            . ipv4: CidrBlock, Cidrs, PrivateIp, PrivateIpAddress, PublicIp, CustomerOwnedIp,
                    TransitGatewayCidrBlocks, CarrierIp, DestinationCidrBlock, CidrIp, CidrIpv4
            . ipv6: Ipv6CidrBlock, DestinationIpv6CidrBlock, Ipv6Address, CidrIpv6
        . uses ipaddress.network.overlap() function; any overlap will be reported
            . argument is part of network cidr found (its an ip or subnet of found cidr)
            . argument cidr contains ip or cidr found (its the network or supernet of found ip or cidr)
            . argument ip directly matches found ip
            . will NOT match 2 IPs that might be in the same network (no way of knowing)
        . when a match is found, a yellow 'Match Found' will be written next to the match on screen
        . if -ip and -split are used with JSON output, highlighting is disabled ('#Match Found!#' is used)
        . may find customer owned ip but generally will not find customer owned ip pools

    Examples:
        vpc-repr.py
            . profile and region will default to environment
            . all VPCs in the region will be reported (except for the default VPC)
            . all content sections will be included in stdout
            . complete json will be written to vpc-repr.json
            . html will be output to stdout

        vpc-repr.py -profile prod -region us-east-1 -j
            . profile and region are overridden and Boto3 will look for profile in config file for credentials
            . all VPCs in the us-east-1 region will be reported (except for the default VPC)
            . all content sections will be included in stdout
            . complete json will be written to vpc-repr.json
            . json will be output to stdout

        vpc-repr.py -vpc-ids vpc-1 vpc-2 vpc-3 -j vpc123.json -ci -na -sg -sn -rt
            . profile and region will default to environment
            . 3 VPCs will be reported on: vpc-1, vpc-2 and vpc-3
            . the VPC shell, CIDRs, NACLs, Security Groups, Subnets and Route Tables will be output to stdout
            . complete json will be written to vpc123.json
            . json will be output to stdout

        vpc-repr.py -f vpc123.json -vpc-ids vpc-2 -gw -rt -w
            . vpc123.json will be read in instead of using AWS
            . 1 VPC will be reported on: vpc-2
            . the VPC shell, Gateways and Route Tables will be output to stdout
            . nothing will be written to vpc-repr.json
            . html will be output to stdout

        vpc-repr.py -f vpc123.json -vpc-ids vpc-2 -ip 10.10.10.0
            . vpc123.json will be read in instead of using AWS
            . 1 VPC will be reported on: vpc-2
            . all content sections will be included in stdout
            . nothing will be written to vpc-repr.json
            . html will be output to stdout
            . ip 10.10.10.0 will be changed to 10.10.10.0/32
            . 10.10.10.0/32 will be used to find IPv4 network overlaps
            . overlapping addresses in stdout will be highlighted with 'Match Found!'

        vpc-repr.py -f vpc123.json -vpc-ids vpc-2 -ip 10.10.10.0/24 -j
            . vpc123.json will be read in instead of using AWS
            . 1 VPC will be reported on: vpc-2
            . all content sections will be included in stdout
            . nothing will be written to vpc-repr.json
            . json will be output to stdout
            . 10.10.10.0/24 will be used to find IPv4 network overlaps
            . overlapping addresses in stdout will be highlighted with 'Match Found!'
    """
    parser = argparse.ArgumentParser(description='VPC Report Generator', epilog=argv_epilog, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('-filename', '-f', nargs=1, help='Input JSON filename (override read from AWS)')
    parser.add_argument('-profile', nargs=1, help='AWSCLI profile to use (override environment settings)')
    parser.add_argument('-region', nargs=1, help='AWS Region to report on (override environment settings)') 
    parser.add_argument('-vpc-ids', nargs='+', metavar='vpc-id', help='When specified, limits to one or more VPC IDs versus all VPCs in the Region')
    parser.add_argument('-j', '-json', nargs='?', const='NOFILE', metavar='filename', help='Output JSON to stdout (unless -w specified), optionally specify filename to override vpc-repr.json') 
    parser.add_argument('-split', nargs='?', const='name', choices=['name', 'id'], metavar='name|id', help='Instead of stdout, output JSON/HTML is written to multiple files using VPC name or id as filename') 
    parser.add_argument('-w', '-web', action='store_true', help='Output HTML to stdout')
    parser.add_argument('-ip', nargs=1, help='IP Search - enter IP Address or Network with prefix (e.g. 10.10.10.10 or 10.10.10.0/24)') 
    parser.add_argument('-verbose', action='store_true', help='Display additonal help on -ip switch and command line examples')
    parser.add_argument('-az', action='store_true', help='Show Availability Zones')
    parser.add_argument('-ci', action='store_true', help='Show CIDR Blocks')
    parser.add_argument('-do', action='store_true', help='Show DHCP Options')
    parser.add_argument('-ep', action='store_true', help='Show Endpoints')
    parser.add_argument('-gw', action='store_true', help='Show Gateways')
    parser.add_argument('-na', action='store_true', help='Show NACLs')
    parser.add_argument('-ni', action='store_true', help='Show Network Interfaces')
    parser.add_argument('-pc', action='store_true', help='Show Peering Connections')
    parser.add_argument('-rt', action='store_true', help='Show Route Tables')
    parser.add_argument('-ta', action='store_true', help='Show VPC Tags')
    parser.add_argument('-sh', action='store_true', help='Show Sharing - reserved for future use')
    parser.add_argument('-sn', action='store_true', help='Show Subnets')
    parser.add_argument('-sg', action='store_true', help='Show Security Groups')
    parser.add_argument('-vp', action='store_true', help='Show VPNs - reserved for future use')
    args = parser.parse_args()

    # -vp or -sh
    if args.sh is True or args.vp is True:
        raise AttributeError('-sh and -vp switches are not yet supported')

    # -verbose
    if args.verbose is True:
        print(argv_epilog, argv_verbose)
        sys.exit()

    # input filename and it exists?
    if args.filename is not None:
        read_mode = True
        if not os.path.exists(args.filename[0]):
            raise FileNotFoundError(f'{args.filename[0]} not found')

    # open output -j filename or fail
    if read_mode is False:
        if args.j is not None and args.j != "NOFILE":
            json_fh = open(args.j, mode='w')
        else:
            json_fh = open('vpc-repr.json', mode='w')

    # set stdout output indicators
    out = "json"
    if args.w is True or args.j == None:
        out = "html"

    ## get input

    # read from json file 
    if read_mode is True:
        vpc_fh = open(args.filename[0], mode='r')
        vpcs = json.load(vpc_fh)
        vpc_fh.close()
        repr_title = "unknown region"
        if "Region" in vpcs:
            repr_title = vpcs['Region']
        region = repr_title
        repr_date = os.path.getmtime(args.filename[0])
        repr_date = datetime.datetime.fromtimestamp(repr_date)
        repr_date = repr_date.strftime("%m/%d/%y %I:%M %p")
        repr_title += f" ({args.filename[0]} saved on {repr_date})"

    # or get data from AWS
    else:
        # determine session parameters, start session, get client
        region = None
        profile = None
        if args.region:
            region = args.region[0]
        if args.profile:
            profile = args.profile[0]
        new_session = boto3.Session(region_name=region, profile_name=profile)
        repr_title = new_session.region_name
        ec2 = new_session.client('ec2')

        # get vpc list (from argv or all)
        if args.vpc_ids is None:
            vpcs = ec2.describe_vpcs()
        else:
            vpcs = ec2.describe_vpcs(VpcIds=args.vpc_ids)

        # remove http response data from dict
        del vpcs['ResponseMetadata']

        # add region to vpcs to save in json file
        vpcs['Region'] = repr_title

        # get prefix list definitions
        prefix_dict = {}
        tmp = ec2.describe_prefix_lists()
        for prefix in tmp['PrefixLists']:
            prefix_dict[prefix['PrefixListId']] = prefix['PrefixListName']

        # get the az list once
        az_dict = ec2.describe_availability_zones()
        del az_dict['ResponseMetadata']

        ## collect items for vpcs in the opposite direction (i.e. item -> vpc versus vpc -> item)
        # egress only internet gateways
        eoig_dict = ec2.describe_egress_only_internet_gateways()
        del eoig_dict['ResponseMetadata']

        # internet gateways
        ig_dict = ec2.describe_internet_gateways()
        del ig_dict['ResponseMetadata']

        # nat gateways
        ng_dict = ec2.describe_nat_gateways()
        del ng_dict['ResponseMetadata']

        # eliminate default vpc
        for i in range(len(vpcs['Vpcs'])):
            if vpcs['Vpcs'][i]['IsDefault'] is True:
                del vpcs['Vpcs'][i]
                break

        ## process all vpcs to build each vpc object
        for vpc in vpcs['Vpcs']:

            # get id for current vpc
            vpc_id = vpc['VpcId']

            # save subnet names for other sections to use
            sn_names_dict = {} # sn_id -> sn_name
            tmp = ec2.describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': [f"{vpc_id}"]}])
            for sn in tmp['Subnets']:

                # get subnet name from tags if it exists
                sn_names_dict[sn['SubnetId']] = get_tag_name(sn)

            # azs
            vpc['AvailabilityZones'] = az_dict['AvailabilityZones']

            # dhcp options
            if 'DhcpOptionsId' in vpc and vpc['DhcpOptionsId'] != "":
                tmp = ec2.describe_dhcp_options(DhcpOptionsIds=[vpc['DhcpOptionsId']])
                vpc['DhcpOptions'] = tmp['DhcpOptions']

            # egress only internet gateways
            for g in eoig_dict['EgressOnlyInternetGateways']:
                for a in g['Attachments']:
                    if a['VpcId'] == vpc_id:
                        vpc['EgressOnlyInternetGateways'] = [g]

            # internet gateway
            for g in ig_dict['InternetGateways']:
                for a in g['Attachments']:
                    if a['VpcId'] == vpc_id:
                        vpc['InternetGateways'] = [g]

            # nat gateways
            for g in ng_dict['NatGateways']:
                if g['VpcId'] == vpc_id:
                    if "NatGateways" in vpc:
                        vpc['NatGateways'].append(g)
                    else:
                        vpc['NatGateways'] = [g]

            # transit gateways
            # get tgw's for vpc and dedupe the ids
            tg_ids = {}
            tmp = ec2.describe_transit_gateway_vpc_attachments(Filters=[{'Name': 'vpc-id', 'Values': [f"{vpc_id}"]}])
            for i in range(len(tmp['TransitGatewayVpcAttachments'])):
                tg_ids[tmp['TransitGatewayVpcAttachments'][i]['TransitGatewayId']] = True
            if len(tg_ids) > 0:
                tmp = ec2.describe_transit_gateways(TransitGatewayIds=sorted(tg_ids.keys()))
                vpc['TransitGateways'] = tmp['TransitGateways']
            
            # network interfaces
            tmp = ec2.describe_network_interfaces(Filters=[{'Name': 'vpc-id', 'Values': [f"{vpc_id}"]}])
            if len(tmp['NetworkInterfaces']) != 0:
                vpc['NetworkInterfaces'] = tmp['NetworkInterfaces']

            # subnets
            tmp = ec2.describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': [f"{vpc_id}"]}])
            if len(tmp['Subnets']) != 0:
                vpc['Subnets'] = tmp['Subnets']

            # vpc endpoints
            tmp = ec2.describe_vpc_endpoints(Filters=[{'Name': 'vpc-id', 'Values': [f"{vpc_id}"]}])
            if len(tmp['VpcEndpoints']) != 0:
                vpc['VpcEndpoints'] = tmp['VpcEndpoints']

            # vpc peering connections (requester-vpc-info.vpc-id / accepter-vpc-info.vpc-id) - move from routes
            pcrs = ec2.describe_vpc_peering_connections(Filters=[{'Name': 'requester-vpc-info.vpc-id', 'Values': [f"{vpc_id}"]}])
            pcas = ec2.describe_vpc_peering_connections(Filters=[{'Name': 'accepter-vpc-info.vpc-id', 'Values': [f"{vpc_id}"]}])

            #dedupe peering records with same connection id
            tmp = {}
            if len(pcrs['VpcPeeringConnections']) != 0:
                for pcr in pcrs['VpcPeeringConnections']:
                    tmp[pcr['VpcPeeringConnectionId']] = pcr
            if len(pcas['VpcPeeringConnections']) != 0:
                for pca in pcas['VpcPeeringConnections']:
                    tmp[pca['VpcPeeringConnectionId']] = pca
            if len(tmp) != 0:
                vpc['VpcPeeringConnections'] = []
                for pc in tmp.values():
                    vpc['VpcPeeringConnections'].append(pc)

            # route tables
            tmp = ec2.describe_route_tables(Filters=[{'Name': 'vpc-id', 'Values': [f"{vpc_id}"]}])
            for rt in tmp['RouteTables']:
                for r in rt['Routes']:
                    notes = ""
                    if "DestinationPrefixListId" in r:
                        notes += prefix_dict[r['DestinationPrefixListId']] + " "
                    if "InstanceId" in r:
                        notes += "Instance ID "
                    if "TransitGatewayId" in r:
                        gwa = ec2.describe_transit_gateway_vpc_attachments(Filters=[
                            {'Name': 'transit-gateway-id', 'Values': [f"{r['TransitGatewayId']}"]},
                            {'Name': 'vpc-id', 'Values': [f"{vpc_id}"]}
                            ])
                        for i in range(len(gwa['TransitGatewayVpcAttachments'])):
                            notes += f"{gwa['TransitGatewayVpcAttachments'][i]['TransitGatewayAttachmentId']} ({gwa['TransitGatewayVpcAttachments'][i]['State']}) "
                    if "LocalGatewayId" in r:
                        lgws = ec2.describe_local_gateways(LocalGatewayIds=[r['LocalGatewayId']])
                        notes += f"Local Gateway - Outpost ARN (State): {lgws['LocalGateways'][0]['OutpostArn']} ({lgws['LocalGateways'][0]['State']}) "
                    if "CarrierGatewayId" in r:
                        cgws = ec2.describe_carrier_gateways(CarrierGatewayIds=[r['CarrierGatewayId']])
                        notes += f"Carrier Gateway - State: {cgws['CarrierGateways'][0]['State']} "
                    if "VpcPeeringConnectionId" in r:
                        notes += f"VPC Peering Connection "
                    if notes != "":
                        r['Notes'] = notes
            if len(tmp['RouteTables']) != 0:
                vpc['RouteTables'] = tmp['RouteTables']

            # security groups
            tmp = ec2.describe_security_groups(Filters=[{'Name': 'vpc-id', 'Values': [f"{vpc_id}"]}])
            for sg in tmp['SecurityGroups']:
                # get rules
                sgrs = ec2.describe_security_group_rules(Filters=[{'Name': 'group-id', 'Values': [sg['GroupId']]}])
                if len(sgrs) != 0:
                    sg['SecurityGroupRules'] = []
                    for sgr in sgrs['SecurityGroupRules']:
                        sg['SecurityGroupRules'].append(sgr)
            if len(tmp['SecurityGroups']) != 0:
                vpc['SecurityGroups'] = tmp['SecurityGroups']

            # nacls
            tmp = ec2.describe_network_acls(Filters=[{'Name': 'vpc-id', 'Values': [f"{vpc_id}"]}])
            if len(tmp['NetworkAcls']) != 0:
                vpc['NetworkAcls'] = tmp['NetworkAcls']

        # write out vpcs to json output file handle
        json.dump(vpcs, json_fh, indent=2, default=datetime_handler)

    # section limited stdout?
    if True in [args.az, args.ci, args.do, args.ep, args.gw, args.na, args.ni, args.pc, args.rt, args.sg, args.sh, args.sn, args.ta, args.vp]:
        for vpc in vpcs['Vpcs']:
            if not args.az and "AvailabilityZones" in vpc:
                del vpc['AvailabilityZones']
            if not args.ci and "CidrBlock" in vpc:
                del vpc['CidrBlock']   
            if not args.ci and "Ipv6CidrBlockAssociationSet" in vpc:
                del vpc['Ipv6CidrBlockAssociationSet']   
            if not args.ci and "CidrBlockAssociationSet" in vpc:
                del vpc['CidrBlockAssociationSet']   
            if not args.do and "DhcpOptions" in vpc:
                del vpc['DhcpOptions']       
            if not args.ep and "VpcEndpoints" in vpc:
                del vpc['VpcEndpoints']
            if not args.gw and "EgressOnlyInternetGateways" in vpc:
                del vpc['EgressOnlyInternetGateways']
            if not args.gw and "InternetGateways" in vpc:
                del vpc['InternetGateways']
            if not args.gw and "NatGateways" in vpc:
                del vpc['NatGateways']
            if not args.gw and "TransitGateways" in vpc:
                del vpc['TransitGateways']
            if not args.na and "NetworkAcls" in vpc:
                del vpc['NetworkAcls']
            if not args.ni and "NetworkInterfaces" in vpc:
                del vpc['NetworkInterfaces']
            if not args.pc and "VpcPeeringConnections" in vpc:
                del vpc['VpcPeeringConnections']
            if not args.rt and "RouteTables" in vpc:
                del vpc['RouteTables']
            if not args.sg and "SecurityGroups" in vpc:
                del vpc['SecurityGroups']
            if not args.sh:
                pass
            if not args.sn and "Subnets" in vpc:
                del vpc['Subnets']
            if not args.ta and "Tags" in vpc:
                del vpc['Tags']
            if not args.vp:
                pass

    # ip/network search
    if args.ip is not None:
        ip = None
        network = None
        try:
            network = ipaddress.ip_network(args.ip[0])
        except:
            network = None
        if ip is None and network is None:
            print(f"\nUnable to process ip string provided: {args.ip[0]}\n")
            sys.exit(2)

        # convert IP to network, classify input ipv4 or ipv6
        # there is no tool in ipaddress module to see if IP is in a network, but /32 can be used in network.overlaps() method to accomplish the same thing
        if isinstance(network, ipaddress.IPv4Network):
            iptype = 4
        else:
            iptype = 6
        import codecs
        # func to highlight matches on screen
        def findmatch(o, network, ippath):
            global iptype
            if isinstance(ippath[o], list):
                for i in range(len(ippath[o])):
                    try:
                        tip = ipaddress.ip_network(ippath[o][i])
                    except:
                        return
                    if network.overlaps(tip):
                        ippath[o][i] += " #Match Found!#"
                return
            if isinstance(ippath[o], str):
                try:
                    tip = ipaddress.ip_network(ippath[o])
                except:
                    return
            if network.overlaps(tip):
                ippath[o] += " #Match Found!#"
            return

        # func to find a matching key, send to highlight func
        def findip(o, match, network, ippath):
            if isinstance(o, dict):
                for k, v in o.items():
                    if k in match:
                        findmatch(k, network, ippath=o)
                    elif isinstance(v, dict):
                        findip(v, match, network, ippath=v)
                    elif isinstance(v, list):
                        for i in range(len(v)):
                            findip(v[i], match, network, ippath=v)
            elif isinstance(o, list):
                for i in range(len(o)):
                    findip(o[i], match, network, ippath)
            return

        # network.overlaps()
        if iptype == 4:
            match = ['CidrBlock', 'Cidrs', 'PrivateIp', 'PrivateIpAddress', 'PublicIp', 'CustomerOwnedIp', 'TransitGatewayCidrBlocks', 'CarrierIp', 'DestinationCidrBlock', 'CidrIp', 'CidrIpv4']
        else:
            match = ['Ipv6CidrBlock', 'DestinationIpv6CidrBlock', 'Ipv6Address', 'CidrIpv6']

        # run through vpcs to find ips
        for i in range(len(vpcs['Vpcs'])):
            # if list of selected vpc-ids, see if this is excluded
            if args.vpc_ids is not None:
                if vpcs['Vpcs'][i]['VpcId'] not in args.vpc_ids:
                    continue
            findip(vpcs['Vpcs'][i], match, network, ippath=vpcs['Vpcs'][i])

        # split option with json? bypass highlighting code and drop back into normal processing
        if out != "json" or args.split is None:

            # convert dict to string to allow replacing highlight placeholder with a working highlighter
            # this is only needed because json.dumps does not handle terminal control characters
            json_string = json.dumps(vpcs, indent=2, default=datetime_handler)

            if out == "json":
                # json - use terminal colors
                class style():
                    RED = '\033[31m'
                    GREEN = '\033[1;32m'
                    YELLOW = '\033[33m'
                    BLUE = '\033[34m'
                    RESET = '\033[0m'
                repl = style.YELLOW + "Match Found!" + style.RESET
                # run substitution
                tmp = re.sub("#Match Found!#", repl, json_string)
                # System call - may not be needed but some claim it allows colorize functions to work for some reason
                os.system("")
                # send highlighted json to stdout and end
                print(tmp)
                sys.exit()
            else:
                # html output - substitute in place with html
                repl = "<span style='background-color:blue;color:yellow;'>Match Found!</span>"
                tmp = re.sub("#Match Found!#", repl, json_string)
                del json_string
                vpcs = json.loads(tmp)
                del tmp

    # json to stdout
    if out == "json":
        if args.split is None:
            print(json.dumps(vpcs, indent=2, default=datetime_handler))
        else:
            # json to split output files
            for vpc in vpcs['Vpcs']:
                vpc_id = vpc['VpcId']
                if args.split == "name":
                    vpc_file = get_tag_name(vpc)
                    if vpc_file == "":
                        vpc_file = vpc_id
                else:
                    vpc_file = vpc_id
                vpct = {'Vpcs': [vpc]}
                vpct['Region'] = region
                with open(f'{vpc_file}.json', mode='w') as vf:
                    json.dump(vpct, vf, indent=2, default=datetime_handler)

    # html to stdout or split
    else:
        if args.vpc_ids is not None and args.split is None:
            partial = "Partial "
        else:
            partial = ""

        def html_header(dest):
            print("<!DOCTYPE html>", file=dest)
            print("<html>", file=dest)
            print("<div class='container'>", file=dest)
            print(f"<head><p style='font-size:150%;text-align:center;color:blue;'>{partial}VPC Configuration Report for {repr_title}<br>{now}", file=dest)
            if args.ip is not None:
                print(f"<br>IP Search: {args.ip[0]}", file=dest)
            print("""<style>h1 {margin-top:10px} h1, h3, h4, h5, h6 {margin-bottom:0px;} h3, h4 {margin-top:5px;}
                            h2 {margin-bottom:5px;} td, th {padding: 0px 5px 0px 5px; text-align:left;}

                            .container {
                                //width: 90%;
                                margin: 0px 35px;
                            }

                            .accordion, .accordion2 {
                                background-color: #f9f9f9;
                                color: #000;
                                cursor: pointer;
                                border: none;
                                outline: none;
                                text-align: left;
                                font-weight: bold;
                                font-family: 'Times New Roman';
                                font-size: 15px;
                                min-width: 50%;
                                transition: 175ms;
                            }

                            .active, .accordion:hover, .active2, .accordion2:hover {
                                background-color: #e9e9e9;
                            }

                            .accordion:after, .accordion2:after {
                                background-color: #f9f9f9;
                                content: '\\002B';
                                color: #000;
                                font-weight: bold;
                                float: right;
                                margin-left: 5px;
                            }

                            .active:after, .active2:after {
                                content: '\\2212';
                                background-color: #e9e9e9;
                            }

                            .sect, .sect2 {
                                background-color: white;
                                max-height: 0px;
                                overflow: hidden;
                                transition: max-height 175ms ease-out;
                            }
                    </style>""", file=dest)
            print(f"<title>VPC Configuration Report ({repr_title})</title>", file=dest)
            print("</head><body>", file=dest)

        def html_vpc_sections(dest, vpc, vpc_name):
            # get id for current vpc
            vpc_id = vpc['VpcId']

            # save subnet names for other sections to use
            sn_names_dict = {} # sn_id -> sn_name
            if "Subnets" in vpc:
                for sn in vpc['Subnets']:
                    sn_names_dict[sn['SubnetId']] = get_tag_name(sn)

            # vpc name and id heading, along with current state
            # owner, tenancy
            print(f"<hr><h1><span style='color:blue;'>{vpc_name}</span> {vpc_id} ({vpc['State']})</h1>", file=dest)
            print(f"Owner: {vpc['OwnerId']}, Tenancy: {vpc['InstanceTenancy']}<br>", file=dest)

            # azs
            if "AvailabilityZones" in vpc:
                az_dict = {}
                for i in range(len(vpc['AvailabilityZones'])):
                    messages = ""
                    for m in vpc['AvailabilityZones'][i]['Messages']:
                        messages += f"{m['Message']} "
                    az_dict[vpc['AvailabilityZones'][i]['ZoneName']] = f"<tr><td>{vpc['AvailabilityZones'][i]['ZoneName']}<td>{vpc['AvailabilityZones'][i]['ZoneId']}<td>{vpc['AvailabilityZones'][i]['State']}<td>{messages}"
                azs = ""
                for k in sorted(az_dict):
                    azs += az_dict[k]
                print(f"{button}Availability Zones{div}<table><tbody>", file=dest)
                print(azs, file=dest)
                print("</table></div>", file=dest)

            # cidrs
            if "CidrBlock" in vpc:
                print(f"{button}CIDR Blocks{div}<table><tbody>{tr}IPv4{space}", file=dest)
                for c in range(len(vpc['CidrBlockAssociationSet'])):
                    print(f"{vpc['CidrBlockAssociationSet'][c]['CidrBlock']} ({vpc['CidrBlockAssociationSet'][c]['CidrBlockState']['State']}) ", file=dest)
                if "Ipv6CidrBlockAssociationSet" in vpc:
                    print(f"{tr}IPv6{space}", file=dest)
                    for c in range(len(vpc['Ipv6CidrBlockAssociationSet'])):
                        print(f"{vpc['Ipv6CidrBlockAssociationSet'][c]['Ipv6CidrBlock']} ({vpc['Ipv6CidrBlockAssociationSet'][c]['Ipv6CidrBlockState']['State']}) ", file=dest)
                print("</table></div>", file=dest)

            # dhcp options
            if "DhcpOptions" in vpc:
                print(f"{button}DHCP Options ({vpc['DhcpOptionsId']}){div}<table><tbody>", file=dest)
                for d in vpc['DhcpOptions'][0]['DhcpConfigurations']:
                    print(tr+d['Key']+space, file=dest)
                    for v in d['Values']:
                        print(f"{v['Value']} ", file=dest)
                print("</table></div>", file=dest)

            ## gateways
            if "EgressOnlyInternetGateways" in vpc or "InternetGateways" in vpc or "NatGateways" in vpc or "TransitGateways" in vpc:
                print(f"{button}Gateways{div}<table><tbody>", file=dest)

                # egress only internet gateways
                eoig_dict = {}
                if "EgressOnlyInternetGateways" in vpc:
                    for g in vpc['EgressOnlyInternetGateways']:
                        gid = g['EgressOnlyInternetGatewayId']
                        for a in g['Attachments']:
                            s = a['State']
                            v = a['VpcId']
                            eoig_dict[v] = [gid, s]
                    print(f"{tr}Egress Only Internet Gateway{space}{eoig_dict[vpc_id][0]} ({eoig_dict[vpc_id][1]})", file=dest)

                # internet gateway
                ig_dict = {}
                if "InternetGateways" in vpc:
                    for g in vpc['InternetGateways']:
                        gid = g['InternetGatewayId']
                        for a in g['Attachments']:
                            s = a['State']
                            v = a['VpcId']
                            ig_dict[v] = [gid, s]
                    print(f"{tr}Internet Gateway{space}{ig_dict[vpc_id][0]} ({ig_dict[vpc_id][1]})", file=dest)

                # nat gateways
                ng_dict = {}
                if "NatGateways" in vpc:
                    for g in vpc['NatGateways']:
                        v = g['VpcId']
                        gid = g['NatGatewayId']
                        s = g['State']
                        ct = g['ConnectivityType']
                        ips = ""
                        if "NatGatewayAddresses" in g:
                            sep = ""
                            for nga in g['NatGatewayAddresses']:
                                ips += f"{sep}{nga['NetworkInterfaceId']}: {nga['PrivateIp']}↔{nga['PublicIp']}"
                                sep = ", "
                        sn = g['SubnetId']
                        if v in ng_dict:
                            ng_dict[v].append([gid, s, ct, ips, sn])
                        else:
                            ng_dict[v] = [[gid, s, ct, ips, sn]]
                    for i in range(len(ng_dict[vpc_id])):
                        print(f"{tr}NAT Gateway{space}{ng_dict[vpc_id][i][0]} ({ng_dict[vpc_id][i][1]}, {ng_dict[vpc_id][i][2]})<td>{ng_dict[vpc_id][i][3]}<td>{ng_dict[vpc_id][i][4]}", file=dest)

                # transit gateways
                # get tgw's for vpc and dedupe the ids
                if "TransitGateways" in vpc:
                    for i in range(len(vpc['TransitGateways'])):
                        print(f"{tr}Transit Gateway{space}{vpc['TransitGateways'][i]['TransitGatewayId']} ({vpc['TransitGateways'][i]['State']})<td>{vpc['TransitGateways'][i]['Description']}", file=dest)

                # end gateways
                print(f"</table></div>", file=dest)

            # network interfaces
            if 'NetworkInterfaces' in vpc:
                print(f"{button}Network Interfaces{div}<table><tbody>", file=dest)
                nif_dict = {}
                print("<tr><th>Description<th>Att. Status<th>I/F Status<th>AZ<th>Subnet Name<th>Subnet ID<th>SG Names<th>SG IDs<th>Network I/F ID<th>Private IP<th>Other Private IPs<th>IPv4 Prefixes<tbody>", file=dest)
                for nif in vpc['NetworkInterfaces']:
                    if "Groups" in nif and len(nif['Groups']) > 0:
                        sg_names = ""
                        sg_ids = ""
                        sep = ""
                        for g in nif['Groups']:
                            sg_names += sep + g['GroupName']
                            sg_ids += sep + g['GroupId']
                            sep = ", "
                    else:
                        sg_names = "-"
                        sg_ids = "-"
                    more_ips = "-"
                    if "PrivateIpAddresses" in nif and len(nif['PrivateIpAddresses']) > 1:
                        more_ips = ""
                        for i in range(len(nif['PrivateIpAddresses'])):
                            if not nif['PrivateIpAddresses'][i]['Primary']:
                                more_ips += nif['PrivateIpAddresses'][i]['PrivateIpAddress'] + " "
                    prefix4 = "-"
                    if "Ipv4Prefixes" in nif:
                        prefix4 = ""
                        for i in range(len(nif['Ipv4Prefixes'])):
                            prefix4 += nif['Ipv4Prefixes'][i]['Ipv4Prefix'] + " "
                    # prefix6 = "/ "
                    # if "Ipv6Prefixes" in nif:
                    #     for i in range(len(nif['Ipv6Prefixes'])):
                    #         prefix6 += nif['Ipv6Prefixes'][i]['Ipv6Prefix'] + " "
                    if nif['SubnetId'] in sn_names_dict:
                        subnet_name = sn_names_dict[nif['SubnetId']]
                    else:
                        subnet_name = "name n/a"
                    nif_key = str(nif['Description'] + spaces)[:100] + nif['SubnetId'] 
                    nif_dict[nif_key] = f"<tr><td>{nif['Description']}<td>{nif['Attachment']['Status']}<td>{nif['Status']}<td>{nif['AvailabilityZone']}<td>{subnet_name}<td>{nif['SubnetId']}<td>{sg_names}<td>{sg_ids}<td>{nif['NetworkInterfaceId']}<td>{nif['PrivateIpAddress']}<td>{more_ips}<td>{prefix4}"
                # print nifs sorted by desc + subnet id
                for k in sorted(nif_dict):
                    print(nif_dict[k], file=dest)
                print("</table></div>", file=dest)

            # subnets
            if "Subnets" in vpc:
                snitems_dict = {}
                print(f"{button}Subnets{div}<table><thead>", file=dest)
                print("<tr><th>Name<th>ID<th>Default<th>IPv4<th>IPv6<th>AZ<th>AZ ID<th>State<tbody>", file=dest)
                for sn in vpc['Subnets']:

                    # default?
                    default = "-"
                    if sn['DefaultForAz']:
                        default = "Yes"

                    # get ipv6 cidrs
                    cidrs = ""
                    sep = ""
                    if "Ipv6CidrBlockAssociationSet" in sn:
                        for t in range(len(sn['Ipv6CidrBlockAssociationSet'])):
                            cidrs += (f"{sep}{sn['Ipv6CidrBlockAssociationSet'][t]['Ipv6CidrBlock']} {sn['Ipv6CidrBlockAssociationSet'][t]['Ipv6CidrBlockState']['State']}")
                            sep = ", "
                            
                    # construct name from tag (dict), ID and default
                    sn_name = f" {sn['SubnetId']}{default}"

                    # subnet info
                    snitems_key = str(sn_names_dict[sn['SubnetId']]+spaces)[:100] + sn['SubnetId']
                    snitems_dict[snitems_key] = f"<tr><td>{sn_names_dict[sn['SubnetId']]}<td>{sn['SubnetId']}<td>{default}<td>{sn['CidrBlock']}<td>{cidrs}<td>{sn['AvailabilityZone']}<td>{sn['AvailabilityZoneId']}<td>{sn['State']}"
                # print subnet info sorted by name + id
                for k in sorted(snitems_dict):
                    print(snitems_dict[k], file=dest)
                print("</table></div>", file=dest)

            # vpc endpoints
            if "VpcEndpoints" in vpc:
                print(f"{button}VPC Endpoints{div}<table><thead>", file=dest)
                vpce_dict = {}
                print("<tr><th>Endpoint ID<th>Endpoint Type<th>Service Name<th>State<th>Route Table IDs<th>Private DNS Enabled<tbody>", file=dest)
                for vpce in vpc['VpcEndpoints']:
                    if len(vpce['RouteTableIds']) > 0:
                        rt_ids =  ""
                        sep = ""
                        for i in range(len(vpce['RouteTableIds'])):
                            rt_ids += f"{sep}{vpce['RouteTableIds'][i]}"
                            sep = ", "
                    else:
                        rt_ids = "-"
                    vpce_dict[vpce['VpcEndpointId']] = f"<tr><td>{vpce['VpcEndpointId']}<td>{vpce['VpcEndpointType']}<td>{vpce['ServiceName']}<td>{vpce['State']}<td>{rt_ids}<td>{vpce['PrivateDnsEnabled']}"
                # print vpces sorted by endpoint id
                for k in sorted(vpce_dict):
                    print(vpce_dict[k], file=dest)
                print("</table></div>", file=dest)

            # vpc peering connections
            if "VpcPeeringConnections" in vpc:
                print(f"{button}VPC Peering Connections{div}<table><thead>", file=dest)
                print("<tr><th>Connection ID<th>Requester ID<th>Requester VPC<th>Requester CIDRs<th>Accepter ID<th>Accepter VPC<th>Accepter CIDRs<th>Status<tbody>", file=dest)
                for pc in vpc['VpcPeeringConnections']:
                    rcidr = ""
                    sep = ""
                    if "CidrBlockSet" in pc['RequesterVpcInfo']:
                        for cidr in pc['RequesterVpcInfo']['CidrBlockSet']:
                            rcidr += f"{sep}{cidr['CidrBlock']}"
                            sep = ", "
                    if "Ipv6CidrBlockSet" in pc['RequesterVpcInfo']:
                        for cidr in pc['RequesterVpcInfo']['Ipv6CidrBlockSet']:
                            rcidr += f"{sep}{cidr['Ipv6CidrBlock']}"
                            sep = ", "
                    acidr = ""
                    sep = ""
                    if "CidrBlockSet" in pc['AccepterVpcInfo']:
                        for cidr in pc['AccepterVpcInfo']['CidrBlockSet']:
                            acidr += f"{sep}{cidr['CidrBlock']}"
                            sep = ", "
                    if "Ipv6CidrBlockSet" in pc['AccepterVpcInfo']:
                        for cidr in pc['AccepterVpcInfo']['Ipv6CidrBlockSet']:
                            acidr += f"{sep}{cidr['Ipv6CidrBlock']}"
                            sep = ", "
                    print(f"<tr><td>{pc['VpcPeeringConnectionId']}<td>{pc['RequesterVpcInfo']['OwnerId']}<td>{pc['RequesterVpcInfo']['VpcId']}<td>{rcidr}<td>{pc['AccepterVpcInfo']['OwnerId']}<td>{pc['AccepterVpcInfo']['VpcId']}<td>{acidr}<td>{pc['Status']['Code']}", file=dest)
                print("</table></div>", file=dest)

            # route tables
            if "RouteTables" in vpc:
                print(f"{button2}Route Tables{div2}<table><tbody><tr><td>", file=dest)
                for rt in vpc['RouteTables']:

                    # get table name from tags if it exists
                    rt_name = get_tag_name(rt)
                    
                    # route table name and id
                    print(f"<h4><span style='color:blue;'>{rt_name} ({rt['RouteTableId']})</span></h4>", file=dest)

                    # put route table items in a big table for readability
                    print(f"<table style='min-width:800px'><tbody><tr><td>", file=dest)

                    # list subnet associations
                    print(f"{button}Subnet/Gateway Associations{div}", file=dest)
                    snas_dict = {}
                    print("<table><tbody>", file=dest)
                    for a in rt['Associations']:
                        if a['Main']:
                            snas_dict['Main'] = f"<tr><td>Main ({a['AssociationState']['State']})"
                        elif "SubnetId" in a:
                            if a['SubnetId'] in sn_names_dict:
                                subnet_name = sn_names_dict[a['SubnetId']]
                            else:
                                subnet_name = "name n/a"
                            # key is S + subnet name (lookup from sn_names_dict) + subnet id
                            snas_key = str(f"S{subnet_name} + {spaces}")[:100] + a['SubnetId']
                            snas_dict[snas_key] = f"<tr><td>{subnet_name}<td>{a['SubnetId']} ({a['AssociationState']['State']})"
                        elif "GatewayId" in a:
                            # key is G + gateway id
                            snas_dict[f"G{a['GatewayId']}"] = f"<tr><td>{a['GatewayId']} ({a['AssociationState']['State']})"
                        else:
                            print(f"{tr}This association is not yet supported: {a}")
                    # print snas sorted by group + ids
                    for k in sorted(snas_dict):
                        print(snas_dict[k], file=dest)
                    print("</table></div>", file=dest)

                    # list routes
                    print(f"<tr><td>{button}Routes{div}", file=dest)
                    print("<table><tr><th>Destination<th>Target<th>Status<th>Origin/Propagation<th>Notes<tbody>", file=dest)
                    for r in rt['Routes']:
                        notes = ""
                        if "DestinationCidrBlock" in r:
                            rdest = r['DestinationCidrBlock']
                        elif "DestinationIpv6CidrBlock" in r:
                            rdest = r['DestinationIpv6CidrBlock']
                        elif "DestinationPrefixListId" in r:
                            rdest = r['DestinationPrefixListId']
                        else:
                            rdest = f"This destination is not yet supported: {r}"
                        if "EgressOnlyInternetGatewayId" in r:
                            target = r['EgressOnlyInternetGatewayId']
                        elif "GatewayId" in r:
                            target = r['GatewayId']
                        elif "InstanceId" in r:
                            target = r['InstanceId']
                        elif "NatGatewayId" in r:
                            target = r['NatGatewayId']
                        elif "TransitGatewayId" in r:
                            target = r['TransitGatewayId']
                        elif "LocalGatewayId" in r:
                            target = r['LocalGatewayId']
                        elif "CarrierGatewayId" in r:
                            target = r['CarrierGatewayId']
                        elif "NetworkInterfaceId" in r:
                            target = r['NetworkInterfaceId']
                        elif "VpcPeeringConnectionId" in r:
                            target = r['VpcPeeringConnectionId']
                        else:
                            target = f"This target is not yet supported: {r}"
                        if "Notes" in r:
                            notes = r['Notes']
                        print(f"<tr><td>{rdest}<td>{target}<td>{r['State']}<td>{r['Origin']}<td>{notes}</tr>", file=dest)
                    print("</table></div></table>", file=dest)
                print("</table></div>", file=dest)

            # security groups
            if "SecurityGroups" in vpc:
                # print("<h4 style='text-decoration:underline;'>Security Groups</h4><table><tbody>")
                print(f"{button2}Security Groups{div2}<table><tbody>", file=dest)
                for sg in vpc['SecurityGroups']:

                    # get group name from tags if it exists
                    sg_name = get_tag_name(sg)

                    # group heading
                    print(f"<tr><td><h4><span style='color:blue;'>{sg_name} ({sg['GroupId']})</span></h4>", file=dest)
                    print(f"<tr><td><strong>Group Name:</strong> {sg['GroupName']}<br><strong>Description:</strong> {sg['Description']}<tr><td>", file=dest)

                    # put sg tables in a big table for readability
                    print("<table style='min-width:800px'><tbody><tr><td>", file=dest)

                    # list inbound rules
                    print(f"{button}Inbound Rules{div}", file=dest)
                    print("<table><tr><th>Name<th>Rule ID<th>Protocol<th>Ports<th>Source<th>Description<tbody>", file=dest)

                    for sgr in sg['SecurityGroupRules']:
                        if sgr['IsEgress'] == False:
                            
                            # get rule name from tags if it exists
                            # set other columns
                            sgr_name = get_tag_name(sgr)
                            if sgr['IpProtocol'] in protocols:
                                protocol = protocols[sgr['IpProtocol']]
                            else:
                                protocol = str(sgr['IpProtocol']).upper()
                            if str(sgr['FromPort']) == "-1":
                                ports = "All"
                            else:
                                ports = f"{sgr['FromPort']}-{sgr['ToPort']}"
                            if "CidrIpv4" in sgr:
                                cidr = sgr['CidrIpv4']
                            elif "CidrIpv6" in sgr:
                                cidr = sgr['CidrIpv6']
                            elif "PrefixListId" in sgr:
                                cidr = sgr['PrefixListId']
                            elif "GroupId" in sgr['ReferencedGroupInfo']:
                                cidr = f"{sgr['ReferencedGroupInfo']['GroupId']} ({sgr['ReferencedGroupInfo']['UserId']})"
                            else:
                                cidr = f"{sgr['ReferencedGroupInfo']['VpcPeeringConnectionId']} ({sgr['ReferencedGroupInfo']['VpcId']} {sgr['ReferencedGroupInfo']['PeeringStatus']})"
                            if "Description" in sgr:
                                desc = sgr['Description']
                            else:
                                desc = "-"
                            print(f"<tr><td>{sgr_name}<td>{sgr['SecurityGroupRuleId']}<td>{protocol}<td>{ports}<td>{cidr}<td>{desc}</tr>", file=dest)
                    print("</table></div>", file=dest)

                    # list outbound rules
                    print(f"{button}Outbound Rules{div}", file=dest)
                    print("<table><tr><th>Name<th>Rule ID<th>Protocol<th>Ports<th>Destination<th>Description<tbody>", file=dest)

                    for sgr in sg['SecurityGroupRules']:
                        if sgr['IsEgress'] == True:
                            
                            # get rule name from tags if it exists
                            # set other columns
                            sgr_name = get_tag_name(sgr)
                            if sgr['IpProtocol'] in protocols:
                                protocol = protocols[sgr['IpProtocol']]
                            else:
                                protocol = str(sgr['IpProtocol']).upper()
                            if str(sgr['FromPort']) == "-1":
                                ports = "All"
                            else:
                                ports = f"{sgr['FromPort']}-{sgr['ToPort']}"
                            if "CidrIpv4" in sgr:
                                cidr = sgr['CidrIpv4']
                            elif "CidrIpv6" in sgr:
                                cidr = sgr['CidrIpv6']
                            elif "PrefixListId" in sgr:
                                cidr = sgr['PrefixListId']
                            elif "GroupId" in sgr['ReferencedGroupInfo']:
                                cidr = f"{sgr['ReferencedGroupInfo']['GroupId']} ({sgr['ReferencedGroupInfo']['UserId']})"
                            else:
                                cidr = f"{sgr['ReferencedGroupInfo']['VpcPeeringConnectionId']} ({sgr['ReferencedGroupInfo']['VpcId']} {sgr['ReferencedGroupInfo']['PeeringStatus']})"
                            if "Description" in sgr:
                                desc = sgr['Description']
                            else:
                                desc = "-"
                            print(f"<tr><td>{sgr_name}<td>{sgr['SecurityGroupRuleId']}<td>{protocol}<td>{ports}<td>{cidr}<td>{desc}</tr>", file=dest)
                    print("</table></div></table>", file=dest)
                print("</table></div>", file=dest)

            # nacls
            if "NetworkAcls" in vpc:
                print(f"{button2}Network Access Control Lists{div2}<table><tbody><tr><td>", file=dest)
                for nacl in vpc['NetworkAcls']:

                    # default nacl?
                    default = ""
                    if nacl['IsDefault']:
                        default = " - Default"

                    # get nacl name from tags if it exists
                    nacl_name = get_tag_name(nacl)

                    # nacl heading
                    print(f"<h4><span style='color:blue;'>{nacl_name} ({nacl['NetworkAclId']}{default})</span></h4>", file=dest)

                    # put nacl tables in a big table for readability
                    print("<table style='min-width:800px'><tbody><tr><td>", file=dest)

                    # list subnet associations
                    print(f"{button}Subnet Associations{div}", file=dest)
                    snas_dict = {}
                    print("<table><tbody>", file=dest)
                    for a in nacl['Associations']:
                        if a['SubnetId'] in sn_names_dict:
                            subnet_name = sn_names_dict[a['SubnetId']]
                        else:
                            subnet_name = "name n/a"
                        # key is subnet name (lookup from sn_names_dict) + subnet id
                        snas_key = str(f"{subnet_name} + {spaces}")[:100] + a['SubnetId']
                        snas_dict[snas_key] = f"<tr><td>{subnet_name}<td>{a['SubnetId']}"
                    # print sna sorted by group + ids
                    for k in sorted(snas_dict):
                        print(snas_dict[k], file=dest)
                    print("</table></div>", file=dest)

                    # list inbound rules
                    print(f"{button}Inbound Rules{div}", file=dest)
                    print("<table><tr><th>Rule#<th>Protocol<th>Ports<th>Source<th>Allow/Deny<tbody>", file=dest)
                    for e in nacl['Entries']:
                        if not e['Egress']:
                            if e['Protocol'] in protocols:
                                protocol = protocols[e['Protocol']]
                            else:
                                protocol = e['Protocol']
                            if "IcmpTypeCode" in e:
                                if str(e['IcmpTypeCode']['Code']) == "-1":
                                    protocol += f" All {e['IcmpTypeCode']['Type']}"
                                else:
                                    protocol += f"{e['IcmpTypeCode']['Code']} {e['IcmpTypeCode']['Type']}"
                            if "PortRange" in e:
                                ports = f"{e['PortRange']['From']}-{e['PortRange']['To']}"
                            else:
                                ports = "All"
                            if "CidrBlock" in e:
                                cidr = e['CidrBlock']
                            else:
                                cidr = e['Ipv6CidrBlock']
                            print(f"<tr><td>{e['RuleNumber']}<td>{protocol}<td>{ports}<td>{cidr}<td>{e['RuleAction'].capitalize()}</tr>", file=dest)
                    print("</table></div>", file=dest)

                    # list outbound rules
                    print(f"{button}Outbound Rules{div}", file=dest)
                    print("<table><tr><th>Rule#<th>Protocol<th>Ports<th>Destination<th>Allow/Deny<tbody>", file=dest)
                    for e in nacl['Entries']:
                        if e['Egress']:
                            if e['Protocol'] in protocols:
                                protocol = protocols[e['Protocol']]
                            else:
                                protocol = e['Protocol']
                            if "IcmpTypeCode" in e:
                                if str(e['IcmpTypeCode']['Code']) == "-1":
                                    protocol += f" All {e['IcmpTypeCode']['Type']}"
                                else:
                                    protocol += f"{e['IcmpTypeCode']['Code']} {e['IcmpTypeCode']['Type']}"
                            if "PortRange" in e:
                                ports = f"{e['PortRange']['From']}-{e['PortRange']['To']}"
                            else:
                                ports = "All"
                            if "CidrBlock" in e:
                                cidr = e['CidrBlock']
                            else:
                                cidr = e['Ipv6CidrBlock']
                            print(f"<tr><td>{e['RuleNumber']}<td>{protocol}<td>{ports}<td>{cidr}<td>{e['RuleAction'].capitalize()}</tr>", file=dest)
                    print("</table></div></table>", file=dest)
                print("</table></div>", file=dest)

            # VPC TAGS
            if "Tags" in vpc:
                print(f"{button}Tags{div}<table><tbody>", file=dest)
                tmp = {}
                for t in range(len(vpc['Tags'])):
                    tmp[vpc['Tags'][t]['Key']] = vpc['Tags'][t]['Value']
                for k, v in sorted(tmp.items()):
                    print(tr+k+space+v, file=dest)
                print("</table></div>", file=dest)
        

        def html_footer(dest):
        # eoj - print footer and accordion formatting jscripts
            print("""<hr><p><strong>EOF</strong></p>
                    <script>
                        const accordionBtns = document.querySelectorAll('.accordion');
                        accordionBtns.forEach((accordion) => {
                            accordion.onclick = function () {
                                this.classList.toggle('active');
                                let sect = this.nextElementSibling;
                                if (sect.style.maxHeight) {
                                    // accordion is open, close it
                                    sect.style.maxHeight = null;
                                } else {
                                    // accordion is closed, open it
                                    sect.style.maxHeight = sect.scrollHeight + 'px';
                                }
                            };
                        });
                        const accordionBtns2 = document.querySelectorAll('.accordion2');
                        accordionBtns2.forEach((accordion2) => {
                            accordion2.onclick = function () {
                                this.classList.toggle('active2');
                                let sect2 = this.nextElementSibling;
                                if (sect2.style.maxHeight) {
                                    // accordion is open, close it
                                    sect2.style.maxHeight = null;
                                } else {
                                    // accordion is closed, open it
                                    sect2.style.maxHeight = '100%';
                                }
                            };
                        });
                    </script>
                    </body></div></html>""", file=dest)

        # single html to stdout
        if args.split is None:

            # output html header once
            html_header(sys.stdout)

            # process all vpcs
            for vpc in vpcs['Vpcs']:

                # if list of selected vpc-ids, see if this is excluded
                vpc_id = vpc['VpcId']
                if args.vpc_ids is not None:
                    if vpc_id not in args.vpc_ids:
                        continue

                # pull vpc name from tags if present
                vpc_name = get_tag_name(vpc)

                # output html for vpc
                html_vpc_sections(sys.stdout, vpc, vpc_name)

            # output html footer once
            html_footer(sys.stdout)

        # split into individual html files
        else:

            # process each vpc
            for vpc in vpcs['Vpcs']:

                vpc_id = vpc['VpcId']
                vpc_name = get_tag_name(vpc)
                vpc_file = vpc_name

                # split by id or name not available
                if args.split == "id" or vpc_file == "":
                    vpc_file = vpc_id

                # output html to file
                with open(f'{vpc_file}.html', mode='w') as vf:
                    html_header(vf)
                    html_vpc_sections(vf, vpc, vpc_name)
                    html_footer(vf)

if __name__ == '__main__': main()

