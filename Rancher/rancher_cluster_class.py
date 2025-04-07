"""Module to interact with individual cluster in Rancher"""

# pylint: disable=no-member, protected-access, too-many-arguments, no-name-in-module
from Rancher import rancher

class RancherClusterObject:
    """
    This class is used to interact with individual cluster in Rancher via Rancher API
    """

    def __init__(self, cluster_name, url, access_key, secret_key, verify=False):        # pylint: disable=too-many-arguments
        """
        Args:
            cluster_name: Cluster name in Rancher
            url: Rancher URL
            access_key: Rancher access key
            secret_key: Rancher secret key
            verify: Verify SSL certificate
        """
        self.url = url
        self.client = rancher.Client(
            url=self.url,
            access_key=access_key,
            secret_key=secret_key,
            verify=verify
        )
        self.cluster_name = cluster_name
        self.cluster_id = self.get_cluster_id()

    def get_cluster_id(self):
        """
        Get cluster ID from Rancher
        Returns: Cluster ID
        """
        resp = self.client._get(f"{self.url}/cluster")
        cluster_data = [resp['data'][i] for i in range(0, len(resp['data'])) if
                        self.cluster_name in resp['data'][i]['name']]
        cluster_id = cluster_data[0]['actions']['enableMonitoring'].split('/')[-1].split('?')[0]
        return cluster_id

    def get_cluster_nodes(self, cluster_id):
        """
        Get cluster nodes from Rancher
        Args:
            cluster_id: Cluster ID

        Returns:
            Dictionary of node hostname and node ID
        """
        resp = self.client._get(f"{self.url}/clusters/{cluster_id}/nodes")
        return {x['hostname']: x['id'] for x in resp['data']}

    def get_node_state(self):
        """
        Get node state from Rancher
        Returns: Node state and node dictionary
        """
        nodes_state = []
        nodes_dict = self.get_cluster_nodes(self.cluster_id)
        for _, node_id in nodes_dict.items():
            resp = self.client._get(f"{self.url}/nodes/{node_id}")
            nodes_state.append(resp['state'])
        return nodes_state, nodes_dict

    def are_all_nodes_active(self):
        """
        Check if all nodes are active
        Returns: A Tuple with True/False, Node states, Node dictionary
        """

        states, nodes_dict = self.get_node_state()
        if len(set(states)) == 1:
            return True, states, nodes_dict
        return False, states, nodes_dict

    def delete_cluster(self):
        """
        Delete cluster from Rancher
        Returns: Rancher Response object
        """

        cluster_id = self.get_cluster_id()
        resp = self.client._delete(f"{self.url}/clusters/{cluster_id}")
        return resp

