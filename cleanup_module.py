"""Module with cleanup resources code"""
# pylint: disable=no-name-in-module, import-error, protected-access
import os
import glob
import time
from logging import Logger
from typing import Union
from dotmap import DotMap
from azure.identity import DefaultAzureCredential
from azure.mgmt.containerservice import ContainerServiceClient
from Rancher import rancher


def find_and_set_kubeconfig(process_id: Union[str, int]) -> str:
    """
    Find the kubeconfig file matching the process_id and set it as KUBECONFIG
    Args:
        process_id: process ID to search for
    """
    process_id = str(process_id)
    kubeconfig_dir = os.path.expanduser("~/.kube/")  # Adjust if needed

    # Search for kubeconfig file related to process_id
    possible_configs = glob.glob(f"{kubeconfig_dir}/*{process_id}*")

    if possible_configs:
        kubeconfig_path = possible_configs[0]  # Assuming one match per process ID
        os.environ["KUBECONFIG"] = kubeconfig_path
        print(f"Set KUBECONFIG to {kubeconfig_path}")
    else:
        print(f"No kubeconfig found for process ID: {process_id}")
    return possible_configs[0]


def get_aks_cluster_by_process(
        logger: Logger, process_id: Union[str, int], subscription_id: str) -> tuple:
    """
    Find the AKS cluster created with a process ID.
    Args:
        logger: Logger for the logger
        process_id: process_id with which the AKS cluster is created with
        subscription_id: Azure subscription ID

    Returns: A tuple of AKS cluster name and resource group
        cluster_name: Name of the AKS cluster
        resource_group: Resource group of the AKS cluster
    """
    process_id = str(process_id)
    logger.info(f"Finding AKS cluster for process ID: {process_id}")
    credential = DefaultAzureCredential()
    client = ContainerServiceClient(credential, subscription_id)
    clusters = client.managed_clusters.list()

    for cluster in clusters:
        if process_id in cluster.name:
            return cluster.name, cluster.node_resource_group.split(cluster.name)[0].split("_")[1]
    return None, None


def delete_aks_cluster(
        logger: Logger, cluster_name: str, resource_group: str, subscription_id: str) -> bool:
    """
    Delete an AKS cluster.
    Args:
        logger: Logger for the logger
        cluster_name (str): Name of the AKS cluster.
        resource_group (str): Resource group of the AKS cluster.
        subscription_id (str): Azure subscription ID.
    Returns:
        bool: True if successful, False
    """
    if not cluster_name or not resource_group or not subscription_id:
        logger.warning("Missing parameters. Cannot delete AKS cluster.")
        return False

    try:
        start_time = time.time()
        # Authenticate with Azure
        credential = DefaultAzureCredential()
        aks_client = ContainerServiceClient(credential, subscription_id)

        # Delete the AKS cluster
        logger.info(f"Deleting AKS cluster: {cluster_name} in resource group: {resource_group}")
        logger.info("This may take several minutes.")
        delete_op = aks_client.managed_clusters.begin_delete(resource_group, cluster_name)
        delete_op.result()  # Wait for completion
        if delete_op.status:
            logger.info(f"AKS cluster {cluster_name} deleted successfully.")
            logger.info(f"Time taken in minutes for AKS cleanup: "
                        f"{(time.time() - start_time) / 60:.2f} minutes")
            return True
        logger.warning(f"Failed to cleanup AKS cluster {cluster_name}")
        return False

    except Exception as e:          # pylint: disable=broad-except
        logger.error(f"Error deleting AKS cluster: {e}")
        return False


def delete_kube_config(logger: Logger, kubeconfig_path: str) -> None:
    """
    Delete the kubeconfig file.
    Args:
        logger: Logger for the logger
        kubeconfig_path: Path to the kubeconfig file
    """
    if os.path.exists(kubeconfig_path):
        os.remove(kubeconfig_path)
        logger.info(f"Kubeconfig file '{kubeconfig_path}' deleted.")
    else:
        logger.warning(f"Kubeconfig file '{kubeconfig_path}' not found.")


def cleanup_resources(logger_object: Logger, process_ids: list, config : DotMap) -> None:
    """
    Clean up resources associated with a process ID.
    Args:
        logger_object: Logger instance
        process_ids: list of process IDs to clean up
        config: Configuration  data from the config json
    """
    logger = logger_object
    rancher_client = rancher.Client(
        url=config.rancher_creds.url, acc[?12;4$yess_key=config.rancher_creds.access_key,
                            secret_key=config.rancher_creds.secret_key, verify=False)
    for process_id in process_ids:
        kubeconfig_path = find_and_set_kubeconfig(process_id)
        # Delete vClusters from Rancher
        logger.info("Deleting the vcluster entries from Rancher")
        delete_count = 1
        clusters = rancher_client.list_cluster()
        while True:
            for cluster in clusters['data']:
                if process_id in cluster['name']:
                    logger.info(f"Deleting cluster: {cluster['name']}")
                    if rancher_client.delete(cluster):
                        delete_count += 1
            if 'pagination' in clusters and clusters['pagination'].get('next'):
                clusters = rancher_client._get(clusters['pagination']['next'])
            else:
                break

        # Find and delete the AKS cluster
        logger.info("Deleting the AKS cluster")
        cluster_name, resource_group = get_aks_cluster_by_process(
            logger, process_id, config.azure_creds.subscription_id)
        status = delete_aks_cluster(logger, cluster_name, resource_group,
                           config.azure_creds.subscription_id)
        if status:
            logger.info(f"AKS cluster {cluster_name} deleted successfully.")
        else:
            logger.warning(f"Failed to cleanup AKS cluster {cluster_name}")

        # Delete kubeconfig file
        if kubeconfig_path:
            delete_kube_config(logger, kubeconfig_path)

        logger.info(f"All resources for process ID {process_id} cleaned up successfully.")

