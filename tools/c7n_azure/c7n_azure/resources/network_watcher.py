import uuid

from c7n.filters.core import ValueFilter
from c7n.utils import type_schema
from c7n_azure.provider import resources
from c7n_azure.resources.arm import ArmResourceManager
from c7n_azure.utils import StringUtils, PortsRangeHelper
from azure.core.exceptions import AzureError

from c7n.actions import BaseAction
from c7n.filters import Filter, FilterValidationError
from c7n.filters.core import PolicyValidationError
from c7n.utils import type_schema


@resources.register('networkwatcher')
class NetworkWatcher(ArmResourceManager):
    """Network Watcher Resource

    :example:

    This policy will ensure Network Security Group Flow Logs are enabled and the retention pe    riod is set to greater than or equal to 90 days.

    .. code-block:: yaml

          policies:
           - name: cfb-azure-ensure-that-network-security-group-flow-log-retention-period
             resource: azure.watcher
             filters:
               - or:
                 - type: networksecuritygroup.flow-log
                   key: retentionPolicy
                   op: lt
                   value: 90
                 - type: networksecuritygroup.flow-log
                   key: state
                   op: ne
                   value: Enabled

    """

    class resource_type(ArmResourceManager.resource_type):
        doc_groups = ['NetworkWatcher']

        service = 'azure.mgmt.networkwatcher'
        client = 'NetworkWatcherManagementClient'
        enum_spec = ('profiles', 'list_by_subscription', None)
        default_report_fields = (
            'name',
            'location',
            'resourceGroup'
            'network_watcher_name'
            'network_security_group_id'
            'enabled'
            'retention_policy'
        )
        resource_type = 'Microsoft.NetworkWatcher/networksecuritygroup


@NetworkWatcher.filter_registry.register('networksecuritygroup')
class NetworkSecurityGroupFilter(NetworkSecurityGroupFilter):
   schema = type_schema('NetworkSecurityGroup', required=['type', 'name'],
        rinherit=ValueFilter.schema,
        name=dict(type='string')
    )
