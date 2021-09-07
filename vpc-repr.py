#!/usr/bin/python3

import boto3
import sys
import datetime
# import json

# Usage:
#
#   python vpc-repr.py [region [vpc-id...]] >vpc-repr.html
#
#       session profile defaults to environment settings
#       region defaults but can be overridden, e.g.:
#           python vpc-repr.py us-east-1
#       all vpcs in the region will be reported by default
#       specify region and one or more vpc-ids to limit the output, e.g.:
#           python vpc-repr.py us-east-1 vpc-xxxx vpc-yyyy
#       all output goes to stdout so pipe it into an html file of your choosing
#
# 9/7/2021 Version 1.0, L. Kuhn 
# 9/7/2021 Version 1.0.1, L. Kuhn
#   - fixed transit gateway bug (assumed AWS would return nothing for empty id list; returned all)

now = datetime.datetime.now()
now = now.strftime("%m/%d/%y %I:%M %p")

# region from argv or default profile
if len(sys.argv) >= 2:
    region = sys.argv[1]
    new_session = boto3.Session(region_name=sys.argv[1])
else:
    new_session = boto3.Session()
    region = new_session.region_name
ec2 = new_session.client('ec2')

# if argv has more they are vpc ids
ids = []
if len(sys.argv) >= 3:
    for i in range(2,len(sys.argv)):
        ids.append(sys.argv[i])
    partial = "Partial "
else:
    partial = ""
    ids = False

# set some globals
tr = "<tr><td><strong>"
space = ":</strong><td>"
spaces = " " * 100
protocols = {"-1": "All", "1": "ICMP", "6": "TCP", "17": "UDP"}
button = "<button class='accordion'>"
div = "</button><div class='sect'>"


def main():

    # debugging, inspection, etc.
    # print(json.dumps(ec2.describe_security_group_rules(Filters=[{'Name': 'group-id', 'Values': ['sg-xxxxxxxxxxxxxxxx']}])))
    # sys.exit()

    # html styles
    print("<!DOCTYPE html>")
    print("<html>")
    print("<div class='container'>")
    print(f"<head><p style='font-size:150%;text-align:center;color:blue;'>{partial}VPC Configuration Report for {region}<br>{now}")
    print("""<style>h1 {margin-top:10px} h1, h3, h4, h5, h6 {margin-bottom:0px;} h3, h4 {margin-top:5px;}
                    h2 {margin-bottom:5px;} td, th {padding: 0px 5px 0px 5px; text-align:left;}

                    .container {
                        //width: 90%;
                        margin: 0px 35px;
                    }

                    .accordion {
                        background-color: #f9f9f9;
                        color: #000;
                        cursor: pointer;
                        border: none;
                        outline: none;
                        text-align: left;
                        font-weight: bold;
                        font-family: 'Times New Roman';
                        font-size: 15px;
                        min-width: 400px;
                        transition: 0.4s;
                    }

                    .active, .accordion:hover {
                        background-color: #e9e9e9;
                    }

                    .accordion:after {
                        background-color: #f9f9f9;
                        content: '\\002B';
                        color: #000;
                        font-weight: bold;
                        float: right;
                        margin-left: 5px;
                    }

                    .active:after {
                        content: '\\2212';
                        background-color: #e9e9e9;
                    }

                    .sect {
                        background-color: white;
                        max-height: 0px;
                        overflow: hidden;
                        transition: max-height 0.2s ease-out;
                    }
             </style>""")
    print(f"<title>VPC Configuration Report ({region})</title>")
    print("</head><body>")

    # get vpc list (from argv or all)
    if ids:
        vpcs = ec2.describe_vpcs(VpcIds=ids)
    else:
        vpcs = ec2.describe_vpcs()
    
    # get prefix list definitions
    prefix_dict = {}
    prefixes = ec2.describe_prefix_lists()
    for prefix in prefixes['PrefixLists']:
        prefix_dict[prefix['PrefixListId']] = prefix['PrefixListName']

    # get the az list once
    az_dict = {}
    azs = ec2.describe_availability_zones()
    for i in range(len(azs['AvailabilityZones'])):
        if azs['AvailabilityZones'][i]['State'] != "available":
            td_state = f"<td style='color:red;'>{azs['AvailabilityZones'][i]['State']}"
        else:
            td_state = "<td>available"
        messages = ""
        for m in azs['AvailabilityZones'][i]['Messages']:
            messages += f"{m['Message']} "
        az_dict[azs['AvailabilityZones'][i]['ZoneName']] = f"<tr><td>{azs['AvailabilityZones'][i]['ZoneName']}<td>{azs['AvailabilityZones'][i]['ZoneId']}{td_state}<td>{messages}"
    # save as text for printing in each vpc
    azs = ""
    for k in sorted(az_dict):
        azs += az_dict[k]

    ## collect items for vpcs in the opposite direction (i.e. item -> vpc versus vpc -> item)
    # egress only internet gateways
    eoig_dict = {}
    eoig = ec2.describe_egress_only_internet_gateways()
    for g in eoig['EgressOnlyInternetGateways']:
        gid = g['EgressOnlyInternetGatewayId']
        for a in g['Attachments']:
            s = a['State']
            v = a['VpcId']
            eoig_dict[v] = [gid, s]

    # internet gateways
    ig_dict = {}
    ig = ec2.describe_internet_gateways()
    for g in ig['InternetGateways']:
        gid = g['InternetGatewayId']
        for a in g['Attachments']:
            s = a['State']
            v = a['VpcId']
            ig_dict[v] = [gid, s]

    # nat gateways
    ng_dict = {}
    ng = ec2.describe_nat_gateways()
    for g in ng['NatGateways']:
        v = g['VpcId']
        gid = g['NatGatewayId']
        s = g['State']
        ct = g['ConnectivityType']
        ips = ""
        if 'NatGatewayAddresses' in g:
            sep = ""
            for nga in g['NatGatewayAddresses']:
                ips += f"{sep}{nga['NetworkInterfaceId']}: {nga['PrivateIp']}&harr;{nga['PublicIp']}"
                sep = ", "
        sn = g['SubnetId']
        if v in ng_dict:
            ng_dict[v].append([gid, s, ct, ips, sn])
        else:
            ng_dict[v] = [[gid, s, ct, ips, sn]]

    ## process all vpcs
    for vpci in vpcs['Vpcs']:

        # bypass default vpc
        if vpci['IsDefault'] == True:
            continue
        
        # get id for current vpc
        vpc_id = vpci['VpcId']

        # pull vpc name from tags if present, save the rest for printing
        vpc_name = ""
        tags=f"{button}Tags{div}<table><tbody>"
        t_dict = {}
        if "Tags" in vpci:
            for t in range(len(vpci['Tags'])):
                t_dict[vpci['Tags'][t]['Key']] = vpci['Tags'][t]['Value']
                if vpci['Tags'][t]['Key'] == "Name":
                    vpc_name = vpci['Tags'][t]['Value']
            for k, v in sorted(t_dict.items()):
                tags += tr+k+space+v
        else:
            tags += f"{tr}None"
        tags += "</table></div>"

        # save subnet names for other sections to use
        sn_dict = {} # sn_id -> sn_name
        subnets = ec2.describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': [f"{vpc_id}"]}])
        for sn in subnets['Subnets']:

            # get subnet name from tags if it exists
            sn_dict[sn['SubnetId']] = ""
            for t in range(len(sn['Tags'])):
                if sn['Tags'][t]['Key'] == "Name":
                    sn_dict[sn['SubnetId']] = sn['Tags'][t]['Value']
                    break

        # vpc name and id heading, along with current state
        # owner, tenancy
        print(f"<hr><h1><span style='color:blue;'>{vpc_name}</span> {vpc_id} ({vpci['State']})</h1>")
        print(f"Owner: {vpci['OwnerId']}, Tenancy: {vpci['InstanceTenancy']}<br>")

        # azs (from saved)
        print(f"{button}Availability Zones{div}<table><tbody>")
        print(azs)
        print("</table></div>")

        # cidrs
        print(f"{button}CIDR Blocks{div}<table><tbody>{tr}IPv4{space}")
        for c in range(len(vpci['CidrBlockAssociationSet'])):
            print(f"{vpci['CidrBlockAssociationSet'][c]['CidrBlock']} ({vpci['CidrBlockAssociationSet'][c]['CidrBlockState']['State']}) ")
        if "Ipv6CidrBlockAssociationSet" in vpci:
            print(f"{tr}IPv6{space}")
            for c in range(len(vpci['Ipv6CidrBlockAssociationSet'])):
                print(f"{vpci['Ipv6CidrBlockAssociationSet'][c]['Ipv6CidrBlock']} ({vpci['Ipv6CidrBlockAssociationSet'][c]['Ipv6CidrBlockState']['State']}) ")
        print("</table></div>")

        # dhcp options
        if 'DhcpOptionsId' in vpci and vpci['DhcpOptionsId'] != "":
            print(f"{button}DHCP Options ({vpci['DhcpOptionsId']}){div}<table><tbody>")
            dhcp = ec2.describe_dhcp_options(DhcpOptionsIds=[vpci['DhcpOptionsId']])
            for d in dhcp['DhcpOptions'][0]['DhcpConfigurations']:
                print(tr+d['Key']+space)
                for v in d['Values']:
                    print(f"{v['Value']} ")
            print("</table></div>")

        ## gateways
        print(f"{button}Gateways{div}<table><tbody>")
        no_gws = "&nbsp;<strong>None</strong>"

        # egress only internet gateways
        if vpc_id in eoig_dict:
            print(f"{tr}Egress Only Internet Gateway{space}{eoig_dict[vpc_id][0]} ({eoig_dict[vpc_id][1]})")
            no_gws = ""

        # internet gateway
        if vpc_id in ig_dict:
            print(f"{tr}Internet Gateway{space}{ig_dict[vpc_id][0]} ({ig_dict[vpc_id][1]})")
            no_gws = ""

        # nat gateways
        if vpc_id in ng_dict:
            for i in range(len(ng_dict[vpc_id])):
                print(f"{tr}NAT Gateway{space}{ng_dict[vpc_id][i][0]} ({ng_dict[vpc_id][i][1]}, {ng_dict[vpc_id][i][2]})<td>{ng_dict[vpc_id][i][3]}<td>{ng_dict[vpc_id][i][4]}")
            no_gws = ""

        # transit gateways
        # get tgw's for vpc and dedupe the ids
        tg_ids = {}
        gwa = ec2.describe_transit_gateway_vpc_attachments(Filters=[{'Name': 'vpc-id', 'Values': [f"{vpc_id}"]}])
        for i in range(len(gwa['TransitGatewayVpcAttachments'])):
            tg_ids[gwa['TransitGatewayVpcAttachments'][i]['TransitGatewayId']] = True
        if len(tg_ids) > 0:
            tgws = ec2.describe_transit_gateways(TransitGatewayIds=sorted(tg_ids.keys()))
            for i in range(len(tgws['TransitGateways'])):
                print(f"{tr}Transit Gateway{space}{tgws['TransitGateways'][i]['TransitGatewayId']} ({tgws['TransitGateways'][i]['State']})<td>{tgws['TransitGateways'][i]['Description']}")
                no_gws = ""
        
        # end gateways
        print(f"{no_gws}</table></div>")

        # network interfaces
        nifs = ec2.describe_network_interfaces(Filters=[{'Name': 'vpc-id', 'Values': [f"{vpc_id}"]}])
        if len(nifs['NetworkInterfaces']) != 0:
            print(f"{button}Network Interfaces{div}<table><tbody>")
            nif_dict = {}
            print("<tr><th>Description<th>Att. Status<th>I/F Status<th>AZ<th>Subnet Name<th>Subnet ID<th>SG Names<th>SG IDs<th>Network I/F ID<th>Private IP<tbody>")
            for nif in nifs['NetworkInterfaces']:
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
                nif_key = str(nif['Description'] + spaces)[:100] + nif['SubnetId'] 
                nif_dict[nif_key] = f"<tr><td>{nif['Description']}<td>{nif['Attachment']['Status']}<td>{nif['Status']}<td>{nif['AvailabilityZone']}<td>{sn_dict[nif['SubnetId']]}<td>{nif['SubnetId']}<td>{sg_names}<td>{sg_ids}<td>{nif['NetworkInterfaceId']}<td>{nif['PrivateIpAddress']}"
            # print nifs sorted by desc + subnet id
            for k in sorted(nif_dict):
                print(nif_dict[k])
            print("</table></div>")

        # subnets
        snitems_dict = {}
        print(f"{button}Subnets{div}<table><thead>")
        subnets = ec2.describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': [f"{vpc_id}"]}])
        print("<tr><th>Name<th>ID<th>Default<th>IPv4<th>IPv6<th>AZ<th>AZ ID<th>State<th>ARN<tbody>")
        for sn in subnets['Subnets']:

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
            snitems_key = str(sn_dict[sn['SubnetId']]+spaces)[:100] + sn['SubnetId']
            snitems_dict[snitems_key] = f"<tr><td>{sn_dict[sn['SubnetId']]}<td>{sn['SubnetId']}<td>{default}<td>{sn['CidrBlock']}<td>{cidrs}<td>{sn['AvailabilityZone']}<td>{sn['AvailabilityZoneId']}<td>{sn['State']}<td>{sn['SubnetArn']}"
        # print subnet info sorted by name + id
        for k in sorted(snitems_dict):
            print(snitems_dict[k])
        print("</table></div>")

        # vpc endpoints
        vpces = ec2.describe_vpc_endpoints(Filters=[{'Name': 'vpc-id', 'Values': [f"{vpc_id}"]}])
        if len(vpces['VpcEndpoints']) != 0:
            print(f"{button}VPC Endpoints{div}<table><thead>")
            vpce_dict = {}
            print("<tr><th>Endpoint ID<th>Endpoint Type<th>Service Name<th>State<th>Route Table IDs<th>Private DNS Enabled<tbody>")
            for vpce in vpces['VpcEndpoints']:
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
                print(vpce_dict[k])
            print("</table></div>")

        # vpc peering connections (requester-vpc-info.vpc-id / accepter-vpc-info.vpc-id) - move from routes
        pcrs = ec2.describe_vpc_peering_connections(Filters=[{'Name': 'requester-vpc-info.vpc-id', 'Values': [f"{vpc_id}"]}])
        pcas = ec2.describe_vpc_peering_connections(Filters=[{'Name': 'accepter-vpc-info.vpc-id', 'Values': [f"{vpc_id}"]}])

        #dedupe peering records with same connection id
        pcs = {}
        if len(pcrs['VpcPeeringConnections']) != 0:
            for pcr in pcrs['VpcPeeringConnections']:
                pcs[pcr['VpcPeeringConnectionId']] = pcr
        if len(pcas['VpcPeeringConnections']) != 0:
            for pca in pcas['VpcPeeringConnections']:
                pcs[pca['VpcPeeringConnectionId']] = pca

        # output peering connections
        print(f"{button}VPC Peering Connections{div}<table><thead>")
        if len(pcs) != 0:
            print("<tr><th>Connection ID<th>Requester ID<th>Requester VPC<th>Requester CIDRs<th>Accepter ID<th>Accepter VPC<th>Accepter CIDRs<th>Status<tbody>")
            for pc in pcs.values():
                rcidr = ""
                sep = ""
                if "CidrBlockSet" in pc['RequesterVpcInfo']:
                    for cidr in pc['RequesterVpcInfo']['CidrBlockSet']:
                        rcidr += f"{sep}{cidr['CidrBlock']}"
                        sep = " "
                else:
                    for cidr in pc['RequesterVpcInfo']['Ipv6CidrBlockSet']:
                        rcidr += f"{sep}{cidr['Ipv6CidrBlock']}"
                        sep = " "
                acidr = ""
                sep = ""
                if "CidrBlockSet" in pc['AccepterVpcInfo']:
                    for cidr in pc['AccepterVpcInfo']['CidrBlockSet']:
                        acidr += f"{sep}{cidr['CidrBlock']}"
                        sep = " "
                else:
                    for cidr in pc['AccepterVpcInfo']['Ipv6CidrBlockSet']:
                        acidr += f"{sep}{cidr['Ipv6CidrBlock']}"
                        sep = " "
                print(f"<tr><td>{pc['VpcPeeringConnectionId']}<td>{pc['RequesterVpcInfo']['OwnerId']}<td>{pc['RequesterVpcInfo']['VpcId']}<td>{rcidr}<td>{pc['AccepterVpcInfo']['OwnerId']}<td>{pc['AccepterVpcInfo']['VpcId']}<td>{acidr}<td>{pc['Status']['Code']}")
        else:
            print(f"{tr}None")
        print("</table></div>")

        # route tables
        print("<h4 style='text-decoration:underline;'>Route Tables</h4><table><tbody><tr><td>")
        route_tables = ec2.describe_route_tables(Filters=[{'Name': 'vpc-id', 'Values': [f"{vpc_id}"]}])
        for rt in route_tables['RouteTables']:

            # get table name from tags if it exists
            rt_name = ""
            for t in range(len(rt['Tags'])):
                if rt['Tags'][t]['Key'] == "Name":
                    rt_name = rt['Tags'][t]['Value']
                    break
            
            # route table name and id
            print(f"<h4><span style='color:blue;'>{rt_name} ({rt['RouteTableId']})</span></h4>")

            # put route table items in a big table for readability
            print(f"<table><tbody><tr><td>")

            # list subnet associations
            print(f"{button}Subnet/Gateway Associations{div}")
            snas_dict = {}
            print("<table><tbody>")
            for a in rt['Associations']:
                if a['Main']:
                    snas_dict['Main'] = f"<tr><td>Main ({a['AssociationState']['State']})"
                elif "SubnetId" in a:
                    # key is S + subnet name (lookup from sn_dict) + subnet id
                    snas_key = str(f"S{sn_dict[a['SubnetId']]} + {spaces}")[:100] + a['SubnetId']
                    snas_dict[snas_key] = f"<tr><td>{sn_dict[a['SubnetId']]}<td>{a['SubnetId']} ({a['AssociationState']['State']})"
                elif "GatewayId" in a:
                    # key is G + gateway id
                    snas_dict[f"G{a['GatewayId']}"] = f"<tr><td>{a['GatewayId']} ({a['AssociationState']['State']})"
                else:
                    print(f"{tr}Something Went Wrong")
            # print snas sorted by group + ids
            for k in sorted(snas_dict):
                print(snas_dict[k])
            print("</table></div>")

            # list routes
            print(f"<tr><td>{button}Routes{div}")
            print("<table><tr><th>Destination<th>Target<th>Status<th>Origin/Propagation<th>Notes<tbody>")
            for r in rt['Routes']:
                notes = ""
                if "DestinationCidrBlock" in r:
                    dest = r['DestinationCidrBlock']
                elif "DestinationIpv6CidrBlock" in r:
                    dest = r['DestinationIpv6CidrBlock']
                elif "DestinationPrefixListId" in r:
                    dest = r['DestinationPrefixListId']
                    notes += prefix_dict[r['DestinationPrefixListId']] + " "
                else:
                    dest = "Something Went Wrong"
                if "EgressOnlyInternetGatewayId" in r:
                    target = r['EgressOnlyInternetGatewayId']
                elif "GatewayId" in r:
                    target = r['GatewayId']
                elif "InstanceId" in r:
                    target = r['InstanceId']
                    notes += "Instance ID "
                elif "NatGatewayId" in r:
                    target = r['NatGatewayId']
                elif "TransitGatewayId" in r:
                    target = r['TransitGatewayId']
                    gwa = ec2.describe_transit_gateway_vpc_attachments(Filters=[
                        {'Name': 'transit-gateway-id', 'Values': [f"{r['TransitGatewayId']}"]},
                        {'Name': 'vpc-id', 'Values': [f"{vpc_id}"]}
                        ])
                    for i in range(len(gwa['TransitGatewayVpcAttachments'])):
                        notes += f"{gwa['TransitGatewayVpcAttachments'][i]['TransitGatewayAttachmentId']} ({gwa['TransitGatewayVpcAttachments'][i]['State']}) "
                elif "LocalGatewayId" in r:
                    target = r['LocalGatewayId']
                    lgws = ec2.describe_local_gateways(LocalGatewayIds=[r['LocalGatewayId']])
                    notes += f"Local Gateway - Outpost ARN (State): {lgws['LocalGateways'][0]['OutpostArn']} ({lgws['LocalGateways'][0]['State']}) "
                elif "CarrierGatewayId" in r:
                    target = r['CarrierGatewayId']
                    cgws = ec2.describe_carrier_gateways(CarrierGatewayIds=[r['CarrierGatewayId']])
                    notes += f"Carrier Gateway - State: {cgws['CarrierGateways'][0]['State']} "
                elif "NetworkInterfaceId" in r:
                    target = r['NetworkInterfaceId']
                elif "VpcPeeringConnectionId" in r:
                    target = r['VpcPeeringConnectionId']
                    vpcpcs = ec2.describe_vpc_peering_connections(VpcPeeringConnectionIds=[r['VpcPeeringConnectionId']])
                    notes += f"VPC Peering Connection "
                else:
                    target = "Something Went Wrong"
                print(f"<tr><td>{dest}<td>{target}<td>{r['State']}<td>{r['Origin']}<td>{notes}</tr>")
            print("</table></div></table>")
        print("</table>")

        # security groups
        print("<h4 style='text-decoration:underline;'>Security Groups</h4><table><tbody>")
        sgs = ec2.describe_security_groups(Filters=[{'Name': 'vpc-id', 'Values': [f"{vpc_id}"]}])
        for sg in sgs['SecurityGroups']:

            # get group name from tags if it exists
            sg_name = ""
            if "Tags" in sg:
                for t in range(len(sg['Tags'])):
                    if sg['Tags'][t]['Key'] == "Name":
                        sg_name = sg['Tags'][t]['Value']
                        break

            # group heading
            print(f"<tr><td><h4><span style='color:blue;'>{sg_name} ({sg['GroupId']})</span></h4>")
            print(f"<tr><td><strong>Group Name:</strong> {sg['GroupName']}<br><strong>Description:</strong> {sg['Description']}<tr><td>")

            # put sg tables in a big table for readability
            print("<table><tbody><tr><td>")

            # get all rules for the group id
            sgrs = ec2.describe_security_group_rules(Filters=[{'Name': 'group-id', 'Values': [sg['GroupId']]}])

            # list inbound rules
            print(f"{button}Inbound Rules{div}")
            print("<table><tr><th>Name<th>Rule ID<th>Protocol<th>Ports<th>Source<th>Description<tbody>")

            for sgr in sgrs['SecurityGroupRules']:
                if sgr['IsEgress'] == False:
                    
                    # get rule name from tags if it exists
                    # set other columns
                    sgr_name = ""
                    if "Tags" in sgr:
                        for t in range(len(sgr['Tags'])):
                            if sg['Tags'][t]['Key'] == "Name":
                                sgr_name = sg['Tags'][t]['Value']
                                break
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
                    if 'Description' in sgr:
                        desc = sgr['Description']
                    else:
                        desc = "-"
                    print(f"<tr><td>{sgr_name}<td>{sgr['SecurityGroupRuleId']}<td>{protocol}<td>{ports}<td>{cidr}<td>{desc}</tr>")
            print("</table></div>")

            # list outbound rules
            print(f"{button}Outbound Rules{div}")
            print("<table><tr><th>Name<th>Rule ID<th>Protocol<th>Ports<th>Destination<th>Description<tbody>")

            for sgr in sgrs['SecurityGroupRules']:
                if sgr['IsEgress'] == True:
                    
                    # get rule name from tags if it exists
                    # set other columns
                    sgr_name = ""
                    if "Tags" in sgr:
                        for t in range(len(sgr['Tags'])):
                            if sg['Tags'][t]['Key'] == "Name":
                                sgr_name = sg['Tags'][t]['Value']
                                break
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
                    if 'Description' in sgr:
                        desc = sgr['Description']
                    else:
                        desc = "-"
                    print(f"<tr><td>{sgr_name}<td>{sgr['SecurityGroupRuleId']}<td>{protocol}<td>{ports}<td>{cidr}<td>{desc}</tr>")
            print("</table></div></table>")
        print("</table>")

        # nacls
        print("<h4 style='text-decoration:underline;'>Network Access Control Lists</h4><table><tbody><tr><td>")
        nacls = ec2.describe_network_acls(Filters=[{'Name': 'vpc-id', 'Values': [f"{vpc_id}"]}])
        for nacl in nacls['NetworkAcls']:

            # default nacl?
            default = ""
            if nacl['IsDefault']:
                default = " - Default"

            # get nacl name from tags if it exists
            nacl_name = ""
            if "Tags" in nacl:
                for t in range(len(nacl['Tags'])):
                    if nacl['Tags'][t]['Key'] == "Name":
                        nacl_name = nacl['Tags'][t]['Value']
                        break

            # nacl heading
            print(f"<h4><span style='color:blue;'>{nacl_name} ({nacl['NetworkAclId']}{default})</span></h4>")

            # put nacl tables in a big table for readability
            print("<table><tbody><tr><td>")

            # list subnet associations
            print(f"{button}Subnet Associations{div}")
            snas_dict = {}
            print("<table><tbody>")
            for a in nacl['Associations']:
                # key is subnet name (lookup from sn_dict) + subnet id
                snas_key = str(f"{sn_dict[a['SubnetId']]} + {spaces}")[:100] + a['SubnetId']
                snas_dict[snas_key] = f"<tr><td>{sn_dict[a['SubnetId']]}<td>{a['SubnetId']}"
            # print sna sorted by group + ids
            for k in sorted(snas_dict):
                print(snas_dict[k])
            print("</table></div>")

            # list inbound rules
            print(f"{button}Inbound Rules{div}")
            print("<table><tr><th>Rule#<th>Protocol<th>Ports<th>Source<th>Allow/Deny<tbody>")
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
                    print(f"<tr><td>{e['RuleNumber']}<td>{protocol}<td>{ports}<td>{cidr}<td>{e['RuleAction'].capitalize()}</tr>")
            print("</table></div>")

            # list outbound rules
            print(f"{button}Outbound Rules{div}")
            print("<table><tr><th>Rule#<th>Protocol<th>Ports<th>Destination<th>Allow/Deny<tbody>")
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
                    print(f"<tr><td>{e['RuleNumber']}<td>{protocol}<td>{ports}<td>{cidr}<td>{e['RuleAction'].capitalize()}</tr>")
            print("</table></div></table>")
        print("</table>")

        # VPC TAGS
        print(tags)
    
    # eoj - print footer and formatting jscript
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
            </script>
            </body></div></html>""")

if __name__ == '__main__': main()

