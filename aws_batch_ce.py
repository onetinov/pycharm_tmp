#! /usr/bin/env python
#
# Ansible example
# resources and type=unmanaged are incompatible
# - name: Batch Compute Environment
#   aws_batch:
#     name: "egauth2"
#     type: "unmanaged|managed"
#     state: enabled
#     role: "arn:aws:iam::836438599727:role/service-role/AWSBatchServiceRole"
#     aws_access_key: APIKEY
#     aws_secret_key: APISECR
#     security_token: AWSTOK
#     profile: saml-egauth-admin
#     resources:
#       type: "EC2|SPOT"
#       minvCpus: "123"
#       maxvCpus: "123"
#       desiredvCpus: "123"
#       instanceTypes:
#         - m4.large
#         - r4.xlarge
#       imageId: ami-foobar
#       subnets:
#         - subnet-c5e109ef
#       securityGroupIds:
#         - sg-6964c514
#       ec2KeyPair: "infra"
#       instanceRole: "ecs_node"
#       tags:
#         Name: clusternode
#         type: awesome
#       bidPercentage: 100
#       spotIamFleetRole: "arn:aws:iam::836438599727:role/aws-ec2-spot-fleet-role"

# Defined and caught here so that we can gracefully call module.fail_json()
# on import failures for clearer exit message.
try:
    import boto3
    import json
    from botocore.exceptions import ClientError
    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ec2 import boto3_conn, \
                                     ec2_argument_spec,\
                                     get_aws_connection_info

def create_batch_ce(client, module):
  params = dict()
  params['compute_envs'] = []
  paginator = client.get_paginator('describe_compute_environments')
  compute_envs = paginator.paginate()
  for env in compute_envs:
    for e in env['computeEnvironments']:
      params['compute_envs'].append(e)

  return params

def disable_batch_ce:
  pass

def delete_batch_ce:
  pass

def main():
  argument_spec = ec2_argument_spec()
  argument_spec.update(dict(
    name        = dict(required=True),
    type        = dict(required=True, choices=['managed', 'unmanaged']),
    state       = dict(default='present',
                       choices=['present', 'disabled', 'absent']),
    role        = dict(required=True),
    resources   = dict()
    )
  )

  module = AnsibleModule(
    argument_spec=argument_spec
  )

  if not (HAS_BOTO3):
    module.fail_json(msg='json and boto3 are required.')

  try:
    region, ec2_url, aws_connect_kwargs = \
      get_aws_connection_info(module, boto3=True)
    aws_batch = boto3_conn(module, conn_type='client', resource='batch',
                         region=region, endpoint=ec2_url, **aws_connect_kwargs)
  except ClientError as e:
    module.fail_json(msg="Failed to conect to AWS Batch - {}".format{e})

    state_call = {
        'present': create_batch_ce,
        'disabled': disable_batch_ce,
        'absent': delete_batch_ce
    }
    results = state_call[module.params.get('state')](client=aws_batch,
                                                     module=module)

    module.exit_json(**results)
  # module.exit_json(changed=changed, instance_ids=new_instance_ids,
  #                  instances=instance_dict_array,
  #                  tagged_instances=tagged_instances)

if __name__ == '__main__':
    main()
