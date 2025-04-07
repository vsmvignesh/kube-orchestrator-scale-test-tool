#!/usr/bin/env python3
"""Script to create a test environment for ZKS"""
# pylint: disable=logging-fstring-interpolation,too-many-locals,too-many-arguments,broad-except,no-name-in-module,broad-exception-raised,import-error,too-many-lines
import os
import sys
import time
import json
import logging
import subprocess
import argparse
import socket  # pylint: disable=unused-import
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
import requests
import urllib3
from filelock import FileLock, Timeout
from dotmap import DotMap
from tenacity import retry, stop_after_attempt, wait_exponential
from azure.identity import DefaultAzureCredential
from azure.mgmt.containerservice import ContainerServiceClient
from azure.mgmt.privatedns import PrivateDnsManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.containerservice.models import (
    ManagedClusterAgentPoolProfile,
    ManagedCluster,
    ManagedClusterIdentity,
    ContainerServiceNetworkProfile
)
from tqdm import tqdm
from Rancher import rancher
import cleanup_module

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Logging setup
logfile_name = f"{os.path.splitext(os.path.basename(sys.argv[0]))[0]}_{os.getpid()}.log"
log_dir = os.path.join(os.getcwd(), "logs")
os.makedirs(log_dir, exist_ok=True)
os.makedirs("tmp", exist_ok=True)
log_file = os.path.join(log_dir, logfile_name)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler(log_file), logging.StreamHandler()]
)
logger = logging.getLogger(__name__)
logging.getLogger("azure").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)

KUBECONFIG_LOCK_FILE = "tmp/kubeconfig.lock"
CREATED_CLUSTERS = {}


def progress_bar_timer(time_in_secs: int) -> None:
    """
    Display progress bar timer for waiting.
    :param time_in_secs:
    """
    for _ in tqdm(range(time_in_secs), desc="Waiting", unit="sec"):
        time.sleep(1)

def countdown_timer(time_in_secs: int) -> None:
    """
    Countdown timer for waiting.
    :param time_in_secs:
    """
    for remaining in range(time_in_secs, 0, -1):
        sys.stdout.write(f"\rWaiting: {remaining} seconds remaining...")
        sys.stdout.flush()
        time.sleep(1)
    sys.stdout.write("\rWaiting complete!                          \n")


@contextmanager
def acquire_kubeconfig_lock(vcluster_name: str, retry_attempts=120, retry_delay=15):
    """
    Context manager for acquiring a kubeconfig lock.
    Args:
        vcluster_name: Name of the vCluster
        retry_attempts: Number of retry attempts
        retry_delay: Delay between retries in seconds
    Yields:
        bool: True if lock acquired, False otherwise
    """
    lock = FileLock(KUBECONFIG_LOCK_FILE)
    acquired = False

    try:
        for attempt in range(1, retry_attempts + 1):
            try:
                lock.acquire(timeout=10)
                logger.info(f"Lock acquired for '{vcluster_name}' (Attempt {attempt})")
                acquired = True
                break
            except Timeout:
                if attempt < retry_attempts:
                    logger.info(
                        f"Retrying lock for '{vcluster_name}'... ({attempt}/{retry_attempts})")
                    countdown_timer(retry_delay)
                else:
                    logger.error(
                        f"Failed to acquire lock for '{vcluster_name}' "
                        f"after {retry_attempts} attempts"
                    )
                    break

        yield acquired

    finally:
        if acquired:
            lock.release()
            logger.info(f"Lock released for '{vcluster_name}'")

def read_config_file(config_file_path: str) -> DotMap:
    """
    Reads the configuration file and returns a DotMap object.
    Returns:
        DotMap: The configuration settings
    """
    required_keys = {
        "azure_creds": ["subscription_id", "resource_group", "location", "vm_size"],
        "rancher_creds": ["url", "access_key", "secret_key"]
    }
    with open(config_file_path, "r", encoding='utf-8') as f:
        config = json.load(f)
    config_map = DotMap(config)
    for section, keys in required_keys.items():
        for key in keys:
            if not getattr(config_map.get(section, DotMap()), key, None):
                raise ValueError(f"Missing required config key: {section}.{key}")
    return config_map

def run_command(command: str, timeout=60, check=True) -> tuple:
    """
    Runs a command using the Python inside a virtual environment with a timeout.

    Args:
        command (str): The command to execute.
        timeout (int): The maximum time (in seconds) to wait for the command to complete.
        check (bool): If True, raise an exception if the command fails.

    Returns:
        tuple: (stdout, stderr, exit_code)
    """

    logger.info(f"\n================================\nExecuting command: {command}")
    shell = False
    if isinstance(command, str):
        shell = True
    try:
        result = subprocess.run(
            command,
            shell=shell,
            text=True,
            capture_output=True,
            executable="/bin/bash",
            timeout=timeout,  # Set timeout for execution
            check=check
        )
        # logger.info(
        #     f"\n-----Output------\n{result.stdout}\n----------------- "
        #     f"\nError: {result.stderr}\n----------------- \nExit Code: {result.returncode}\n"
        #     f"================================")
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired as e:
        logger.warning(f"Command timed out: {e}")
        return "", str(e), 1
    except subprocess.CalledProcessError as e:
        logger.error(f"Command failed: {e.stderr}")
        return "", e.stderr, e.returncode


def get_supported_kubernetes_versions(subscription_id: str, location: str) -> list:
    """
    Get the supported Kubernetes versions in the specified location.
    Args:
        subscription_id: Azure subscription ID
        location: Azure region
    Returns:
        list: List of supported Kubernetes
    """
    credential = DefaultAzureCredential()
    aks_client = ContainerServiceClient(credential, subscription_id)
    # Get the supported Kubernetes versions in the specified location
    versions = aks_client.managed_clusters.list_kubernetes_versions(location)
    # Extract available versions
    supported_versions = [v.version for v in versions.values]
    return supported_versions

def req_nodes_for_spot_node_pool(num_vclusters: int) -> int:
    """
    Calculate the number of nodes required for the spot node pool based on the number of vClusters.

    Each vCluster deploys 6 pods.
    # 6 vCluster pods + 1 cattle-cluster-agent + 1 fleet-agent + 2 helm-operation (avg)
    Each node (with 8 vCPUs) can handle a maximum of 22 pods.
    A buffer of 20 additional pods is considered in the calculation.

    :param num_vclusters: Number of vClusters to deploy.
    :type num_vclusters: int or str (convertible to int)
    :return: Number of nodes required in the node pool.
    :rtype: int
    :raises ValueError: If num_vclusters is not an integer or a convertible string.
    """
    # Convert string input to int
    if isinstance(num_vclusters, str):
        if not num_vclusters.isdigit():
            raise ValueError("num_vclusters should be an integer or a numeric string")
        num_vclusters = int(num_vclusters)

    # Validate input type and value
    if not isinstance(num_vclusters, int) or num_vclusters < 0:
        raise ValueError("num_vclusters should be a non-negative integer")

    # Calculation logic
    pods_per_vcluster = 10
    total_pods = (num_vclusters * pods_per_vcluster) + 20  # Buffer
    pods_per_node = 22
    req_nodes_count = total_pods // pods_per_node + (1 if total_pods % pods_per_node else 0)
    req_nodes_count = int(req_nodes_count * 1.2)  # 20% safety margin
    return req_nodes_count

def create_aks_cluster_with_spot(                                               # pylint: disable=too-many-positional-arguments
        subscription_id: str, resource_group: str, cluster_name: str,
        location: str, vm_size: str, num_vclusters, timeout=600):
    """
    Create an AKS cluster with both a system node pool and a spot node pool in one go.
    Args:
        subscription_id (str): Azure subscription ID
        resource_group (str): Azure resource group
        cluster_name (str): AKS cluster name
        location (str): Azure region
        vm_size (str): VM size for the node pools
        num_vclusters (int): Number of vclusters intended to be created
        timeout (int): Timeout in seconds for cluster creation
    Returns:
        Tuple: True if successful, False otherwise
                LRO poller object
    """
    start_time = time.time()
    credential = DefaultAzureCredential()
    aks_client = ContainerServiceClient(credential, subscription_id)

    # Get latest supported Kubernetes version
    supported_versions = get_supported_kubernetes_versions(subscription_id, location)
    latest_k8s_version = max(supported_versions, key=lambda v: tuple(map(int, v.split("."))))
    logger.info(f"Using latest supported Kubernetes version: {latest_k8s_version}")

    logger.info(f"Total required nodes will be around: "
                f"{req_nodes_for_spot_node_pool(num_vclusters)} ")

    # Define network profile with custom DNS
    network_profile = ContainerServiceNetworkProfile(
        load_balancer_sku="standard",
        outbound_type="loadBalancer",
        dns_service_ip="10.0.0.10",  # Default AKS DNS service IP
        service_cidr="10.0.0.0/16"
    )

    # Define the system node pool (required for AKS)
    system_pool_profile = ManagedClusterAgentPoolProfile(
        name="systempool",
        mode="System",  # Required system pool
        count=1,
        vm_size=vm_size,
        os_type="Linux",
        type="VirtualMachineScaleSets",
        enable_auto_scaling=False,
        max_pods=50
    )

    # Define the spot node pool with corrected attributes
    spot_pool_profile = ManagedClusterAgentPoolProfile(
        name="spotnodepool",
        mode="User",
        count=1,
        vm_size=vm_size,
        os_type="Linux",
        type="VirtualMachineScaleSets",
        scale_set_priority="Spot",
        spot_max_price=-1.0,
        scale_set_eviction_policy="Delete",
        enable_auto_scaling=True,
        min_count=1,
        max_count=150,
        max_pods=250,
        node_taints=["kubernetes.azure.com/scalesetpriority=spot:NoSchedule"]
    )

    # Define the cluster with both node pools
    cluster_params = ManagedCluster(
        location=location,
        kubernetes_version=latest_k8s_version,
        dns_prefix=cluster_name,
        agent_pool_profiles=[system_pool_profile, spot_pool_profile],
        enable_rbac=True,
        identity=ManagedClusterIdentity(type="SystemAssigned"),
        network_profile=network_profile
    )

    try:
        # Create the cluster with corrected arguments
        logger.info("Creating AKS cluster with spot node pool... This may take several minutes.")
        poller = aks_client.managed_clusters.begin_create_or_update(
            resource_group, cluster_name, cluster_params)
        cluster_result = poller.result()
        logger.info(f"AKS cluster {cluster_result.name} created successfully.")
        logger.info(f"Time taken: {(time.time() - start_time) / 60:.2f} minutes")

        # Verify spot node pool
        start_time = time.time()
        while time.time() - start_time < timeout:
            spot_pool = aks_client.agent_pools.get(resource_group, cluster_name, "spotnodepool")
            if (spot_pool.provisioning_state == "Succeeded"
                    and spot_pool.power_state.code == "Running"):
                logger.info(f"Spot node pool is running. "
                            f"ScaleSetPriority: {spot_pool.scale_set_priority}, "
                            f"SpotMaxPrice: {spot_pool.spot_max_price}, "
                            f"ScaleSetEvictionPolicy: {spot_pool.scale_set_eviction_policy}")
                return True, poller
            if spot_pool.provisioning_state == "Failed":
                logger.error(f"Spot node pool creation failed: {spot_pool.provisioning_state}")
                return False, poller
            logger.info(f"Spot node pool state: {spot_pool.provisioning_state}. "
                        f"Checking again in 10 seconds.")
            countdown_timer(10)
        logger.error(f"Spot node pool did not reach Running state within {timeout} seconds.")
        return False, poller

    except Exception as e:
        logger.error(f"Error creating AKS cluster with spot node pool: {str(e)}")
        raise

def get_kubeconfig(subscription_id: str, resource_group: str, cluster_name: str) -> str:
    """
    Get the kubeconfig file for the AKS cluster.
    Args:
        subscription_id: Azure subscription ID
        resource_group: Azure resource group
        cluster_name: AKS cluster name

    Returns:
        str: Path to the kubeconfig file
    """
    os.system(f"az aks get-credentials --resource-group "
              f"{resource_group} --name {cluster_name} "
              f"--admin --file ~/.kube/{cluster_name}-config")
    countdown_timer(10)
    credential = DefaultAzureCredential()
    aks_client = ContainerServiceClient(credential, subscription_id)
    kubeconfig = aks_client.managed_clusters.list_cluster_admin_credentials(
        resource_group, cluster_name)

    kubeconfig_path = os.path.join(os.path.expanduser("~/.kube"), f"{cluster_name}-config")
    with open(kubeconfig_path, "wb") as file:
        file.write(kubeconfig.kubeconfigs[0].value)
    os.environ["KUBECONFIG"] = kubeconfig_path
    countdown_timer(2)

    return kubeconfig_path


def get_rancher_registration_token(  # pylint: disable=too-many-positional-arguments
        rancher_url: str, access_key: str, secret_key: str,
        cluster_id: str, max_attempts=5, delay=30) -> str:
    """
    Retrieve or create a registration token for a cluster in Rancher.
    :param rancher_url: Rancher URL
    :param access_key: Rancher access key
    :param secret_key: Rancher secret key
    :param cluster_id: Rancher cluster ID
    :param max_attempts: Maximum number of attempts to retrieve or create the token
    :param delay: Delay in seconds between attempts
    :return: Registration token or None
    """
    auth_header = f"Bearer {access_key}:{secret_key}"
    url = f"{rancher_url}/clusterregistrationtokens?clusterId={cluster_id}"
    for attempt in range(max_attempts):
        reg_command = f"curl -s -k -H \"Authorization: {auth_header}\" \"{url}\""
        raw_response, err, exit_code = run_command(reg_command)
        if exit_code != 0:
            logger.debug(f"Token retrieval attempt {attempt + 1}/{max_attempts} failed: {err}")
            countdown_timer(delay)
            continue
        logger.debug(f"Raw token response: {raw_response}")
        try:
            response_data = json.loads(raw_response)
            if response_data.get("data") and len(response_data["data"]) > 0:
                token = (response_data["data"][0].get("token")
                         or response_data["data"][0].get("name"))
                if token and token != "null":
                    logger.info(f"Retrieved registration token: {token}")
                    return token
            else:
                logger.debug(f"No tokens found for cluster '{cluster_id}', creating one...")
                create_cmd = (
                    f"curl -s -k -X POST -H \"Authorization: {auth_header}\" "
                    f"-H \"Content-Type: application/json\" "
                    f"-d '{{\"clusterId\": \"{cluster_id}\"}}' "
                    f"\"{rancher_url}/clusterregistrationtokens\""  # Removed /v3
                )
                create_response, create_err, create_exit = run_command(create_cmd)
                if create_exit != 0:
                    logger.debug(f"Failed to create token: {create_err}")
                    countdown_timer(delay)
                    continue
                create_data = json.loads(create_response)
                token = create_data.get("token") or create_data.get("name")
                if token and token != "null":
                    logger.info(f"Created registration token: {token}")
                    return token
        except json.JSONDecodeError as e:
            logger.debug(f"Failed to parse token response: {e}\nRaw: {raw_response}")
        countdown_timer(delay)
    logger.error(
        f"Failed to retrieve or create token for cluster '{cluster_id}' "
        f"after {max_attempts} attempts")
    return ""

def patch_for_cattle_cluster_agent(rancher_host: str, rancher_ip: str, namespace: str):
    """
    Patching the cattle-cluster agent
    :param rancher_host: Rancher hostname
    :param rancher_ip: Rancher IP
    """
    logger.info(f"Patching cattle-cluster-agent in {rancher_host}...")
    patch_data = {
        "spec": {
            "template": {
                "spec": {
                    "hostAliases": [
                        {
                            "hostnames": [rancher_host],
                            "ip": rancher_ip
                        }
                    ]
                }
            }
        }
    }

    patch_json = json.dumps(patch_data)  # Convert dict to JSON string

    patch_command = [
        "kubectl", "-n", namespace, "patch", "deployments", "cattle-cluster-agent",
        "--patch", patch_json
    ]
    run_command(' '.join(patch_command))

def check_current_cluster_state(cluster_id: str, rancher_url: str, access_key: str,
                                secret_key: str) -> str:
    """
    Get the current state of the cluster
    Args:
        cluster_id: Cluster ID in Rancher
        rancher_url: Rancher URL
        access_key: Rancher access key
        secret_key: Rancher secret key

    Returns:
        str: Current state of the cluster
    """
    auth_header = {"Authorization": f"Bearer {access_key}:{secret_key}"}
    get_url = f"{rancher_url}/clusters/{cluster_id}"
    response = requests.get(get_url, headers=auth_header, timeout=5, verify=False)
    response.raise_for_status()
    cluster_status = response.json().get("state", "Unknown")
    return cluster_status

def check_if_cluster_moved_from_pending(                # pylint: disable=too-many-positional-arguments
        cluster_id: str, rancher_url: str, rancher_access_key: str,
        rancher_secret_key: str, timeout=90, interval=10
) -> bool:
    """
    Verify if the cluster in Rancher has moved from 'Pending' state.

    Args:
        cluster_id: Cluster ID in Rancher
        rancher_url: Rancher URL
        rancher_access_key: Rancher access key
        rancher_secret_key: Rancher secret key
        timeout: Maximum time (in seconds) to wait for the cluster to move out of 'Pending' state
        interval: Time interval (in seconds) between checks

    Returns:
        bool: True if the cluster is not in 'Pending' state, False otherwise.
    """
    logger.info(f"Checking the current state of cluster: {cluster_id}")
    end_time = time.time() + timeout

    while time.time() < end_time:
        try:
            cluster_status = check_current_cluster_state(
                cluster_id, rancher_url, rancher_access_key, rancher_secret_key)
            if cluster_status.lower() != "pending":
                logger.info(
                    f"Cluster {cluster_id} has moved out of 'Pending' state. "
                    f"Current state: {cluster_status}")
                return True

            logger.info(
                f"Cluster {cluster_id} is still in 'Pending' state. "
                f"Retrying in {interval} seconds...")
        except requests.exceptions.RequestException as e:
            logger.error(f"Error checking cluster state: {e}")

        time.sleep(interval)

    logger.error(
        f"Cluster {cluster_id} did not move out of 'Pending' state within {timeout} seconds.")
    return False

def run_apply_command_with_retries(                                 # pylint: disable=too-many-positional-arguments
        cluster_id: str, rancher_url: str, rancher_access_key: str, rancher_secret_key: str,
        command: str, max_retries=3, interval=30, timeout=300
) -> bool:
    """
    Run a kubectl apply command with retries if the cluster remains in 'Pending' state.

    Args:
        cluster_id: Cluster ID in Rancher
        rancher_url: Rancher URL
        rancher_access_key: Rancher access key
        rancher_secret_key: Rancher secret key
        command: Command to run
        max_retries: Number of times to retry applying the command
        interval: Time (in seconds) between retries
        timeout: Maximum time (in seconds) to wait for the cluster to move from 'Pending' state

    Returns:
        bool: True if the cluster successfully moves out of 'Pending' state, False otherwise.
    """

    for attempt in range(max_retries):
        logger.info(
            f"Attempt {attempt + 1}/{max_retries} of "
            f"Provisioning cluster: {cluster_id}")
        if check_if_cluster_moved_from_pending(
                cluster_id, rancher_url, rancher_access_key, rancher_secret_key, timeout):
            logger.info(f"Cluster {cluster_id} successfully moved out of 'Pending' state.")
            return True
        logger.warning(
            f"Cluster {cluster_id} is still in 'Pending' state. Retrying apply command...")

        try:
            out, err, code = run_command(command)
            logger.info(
                f"\n-----Output------\n{out}\n----------------- "
                f"\nError: {err}\n----------------- \nExit Code: {code}\n"
                f"================================")
        except subprocess.CalledProcessError as e:
            logger.error(f"Error executing apply command: {e.stderr}")

        # Wait before retrying
        if attempt < max_retries - 1:
            logger.info(f"Waiting {interval} seconds before next retry...")
            time.sleep(interval)

    logger.error(f"Failed to move cluster {cluster_id} out of 'Pending' state "
                 f"after {max_retries} retries.")
    return False

def import_cluster_to_rancher(  # pylint: disable=too-many-positional-arguments
        host_cluster_name: str, rancher_url: str, access_key: str, secret_key: str,
        vcluster_name: str, namespace: str, kubeconfig_path: str,
        host_cluster_import: bool=False, parallel: bool=False) -> dict:
    """
    Import an AKS cluster to Rancher with thread-safe kubeconfig handling.
    Args:
        host_cluster_name: AKS Cluster name (e.g., systest-zks-test-cluster-550115)
        rancher_url: Rancher URL
        access_key: Rancher access key
        secret_key: Rancher secret key
        vcluster_name: Name of the vCluster (e.g., vcluster-550115-1)
        namespace: Namespace for the vCluster
        kubeconfig_path: Path to the host cluster kubeconfig
        host_cluster_import: True, if the cluster to be imported is the host cluster
        parallel: True, if the import process is parallelized, which will invoke config file lock
    Returns:
        dict: Response from Rancher API
    """
    client = rancher.Client(
        url=rancher_url, access_key=access_key, secret_key=secret_key, verify=False)

    try:
        if host_cluster_import:
            cluster_name = context = host_cluster_name
        else:
            cluster_name = vcluster_name
            context = f"vcluster_{vcluster_name}_{namespace}_{host_cluster_name}"
            # If importing virtual clusters, we need to acquire the lock
            # to prevent multiple vclusters modifying kubeconfig at the same time
            if parallel:
                with acquire_kubeconfig_lock(vcluster_name) as lock_acquired:
                    if not lock_acquired:
                        raise RuntimeError(
                            f"Failed to acquire kubeconfig lock for {vcluster_name}, "
                            f"aborting import process.")

        with open(kubeconfig_path, "r", encoding='utf-8') as f:
            kubeconfig = f.read()
        response = client.create_cluster(name=cluster_name, kubeconfig=kubeconfig)
        logger.info(f"import_cluster_to_rancher: Cluster '{cluster_name}' created in Rancher.")
        cluster_id = response["id"]
        logger.info(f"Cluster ID: {cluster_id}")
        countdown_timer(5)

        # Get cluster registration token
        token = get_rancher_registration_token(rancher_url, access_key, secret_key, cluster_id)
        if not token:
            raise ValueError("import_cluster_to_rancher: Error retrieving registration token")

        # Download the YAML file
        download_yaml_command = (f"curl --insecure -sfL "
                                 f"{rancher_url}/import/{token}_{cluster_id}.yaml "
                                 f"-o tmp/import-{cluster_name}.yaml")
        run_command(download_yaml_command)
        logger.info(f"import_cluster_to_rancher: YAML file downloaded for cluster {cluster_name}.")

        # form the kubectl apply command to provision cluster
        apply_kubectl = (f"kubectl apply -f tmp/import-{cluster_name}.yaml "
                         f"--validate=false --context={context}")
        if host_cluster_import:
            # If importing host cluster, we don't need to connect to vcluster
            command = apply_kubectl
        else:
            time.sleep(5)
            # Club vcluster connect to the command
            command = (f"KUBECONFIG={kubeconfig_path} "
                       f"vcluster connect {vcluster_name} -n {namespace} -- {apply_kubectl}")

        CREATED_CLUSTERS[cluster_id] = command
        run_command(command)
        logger.info(f"import_cluster_to_rancher: YAML file applied. for cluster '{cluster_name}'")

        # Uncomment the below snippet to patch deployment while trying to import your cluster
        # Which is not managed by Azure cloud

        # patch_cattle_cluster_agent(rancher_url, namespace, kubeconfig_path)
        # rancher_host = rancher_url.split("//")[1].split("/")[0]
        # rancher_ip = socket.gethostbyname(rancher_host)
        # patch_for_cattle_cluster_agent(rancher_host, rancher_ip)

        # Cleanup YAML file
        countdown_timer(5)

        return response

    except Exception as e:
        logger.error(f"import_cluster_to_rancher: Error importing cluster to Rancher: {e}")
        return {}

def wait_for_vcluster_ready(
        cluster_name: str, vcluster_name: str,
        namespace: str, kubeconfig_path: str, timeout=180) -> bool:
    """
    Wait for the vCluster to be ready by checking its pod status.

    Args:
        cluster_name: AKS Cluster name (e.g., systest-zks-test-cluster-550115)
        vcluster_name: Name of the vCluster (e.g., vcluster-550115-1)
        namespace: Namespace for the vCluster
        kubeconfig_path: Path to the host cluster kubeconfig
        timeout: Timeout in seconds

    Returns:
        bool: True if vCluster pod is Running, False otherwise
    """
    logger.info(f"Waiting for vCluster '{vcluster_name}' to be ready...")
    check_command = (
        f"KUBECONFIG={kubeconfig_path} kubectl --context={cluster_name} "
        f"-n {namespace} get pod -l app=vcluster,release={vcluster_name} "
        f"-o jsonpath='{{.items[0].status.phase}}'"
    )
    start_time = time.time()
    while time.time() - start_time < timeout:
        stdout, err, exit_code = run_command(check_command, check=False)
        if exit_code == 0 and stdout.strip() == "Running":
            logger.info(f"vCluster '{vcluster_name}' pod is Running.")
            return True
        if exit_code != 0:
            logger.debug(f"Waiting: kubectl failed - {err}")
        else:
            logger.debug(f"Waiting: pod status is '{stdout.strip()}'")
        countdown_timer(5)
    logger.warning(f"vCluster '{vcluster_name}' not ready after {timeout} seconds.")
    return False

@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=60))
def deploy_vcluster(
        cluster_name: str, namespace: str, vcluster_name: str, kubeconfig_path: str) -> None:
    """
    Deploy a vCluster using the vcluster CLI.
    :param cluster_name: AKS Cluster name
    :param namespace: Namespace for the vCluster
    :param vcluster_name: Name of the vCluster
    :param kubeconfig_path: Path to the host cluster kubeconfig
    """
    run_command(
        f"KUBECONFIG={kubeconfig_path} vcluster create {vcluster_name} "
        f"--namespace={namespace} -f helm.yaml --connect=False")
    if not wait_for_vcluster_ready(cluster_name, vcluster_name, namespace, kubeconfig_path):
        # connect vcluster
        # connect_vcluster(cluster_name, namespace, vcluster_name, kubeconfig_path)
        raise Exception("vCluster not ready")

@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=20))
def connect_vcluster(
        cluster_name: str, namespace: str, vcluster_name: str, kubeconfig_path: str) -> None:
    """
    Connect to a vCluster and verify the context.
    :param cluster_name: AKS Cluster name
    :param namespace: Namespace for the vCluster
    :param vcluster_name: Name of the vCluster
    :param kubeconfig_path: Path to the host cluster kubeconfig
    """
    # Ensure the host cluster context is set before connecting
    run_command(f"KUBECONFIG={kubeconfig_path} kubectl config use-context {cluster_name}")
    run_command(f"KUBECONFIG={kubeconfig_path} vcluster connect {vcluster_name} -n {namespace}")
    if not check_if_context_exist(cluster_name, namespace, vcluster_name, kubeconfig_path):
        raise Exception(f"vCluster '{vcluster_name}' connection failed")  # pylint: disable=broad-except

def check_if_context_exist(
        cluster_name: str, namespace: str, vcluster_name: str, kubeconfig_path: str) -> bool:
    """
    Check if the vCluster context exists.
    Args:
        :param cluster_name: AKS Cluster name
        :param namespace: Namespace for the vCluster
        :param vcluster_name: Name of the vCluster
        :param kubeconfig_path: Path to the host cluster kubeconfig
    :returns
        True if context exists, False otherwise
    """
    context = f"vcluster_{vcluster_name}_{namespace}_{cluster_name}"
    check_command = (f"KUBECONFIG={kubeconfig_path} "
                     f"kubectl config get-contexts {context} --no-headers")
    output, _, exit_code = run_command(check_command, check=False)
    if exit_code == 0:
        output_list = [line.strip() for line in output.splitlines() if line.strip()]
        return any(context in line for line in output_list)
    return False

def link_vnet_to_dns_zone(subscription_id: str, resource_group: str,
                          dns_zone_name: str, cluster_name: str) -> bool:
    """
    Robust VNET to Private DNS linking with full validation
    """
    try:
        credential = DefaultAzureCredential()

        # 1. Get the actual VNET from AKS cluster
        vnet_name = get_vnet_name(subscription_id, resource_group, cluster_name)
        aks_client = ContainerServiceClient(credential, subscription_id)
        cluster = aks_client.managed_clusters.get(resource_group, cluster_name)
        node_rg = cluster.node_resource_group

        # 2. Get complete VNET information
        network_client = NetworkManagementClient(credential, subscription_id)
        vnet = network_client.virtual_networks.get(node_rg, vnet_name)
        logger.info(f"Found VNET: {vnet.name} (ID: {vnet.id})")

        # 3. Verify Private DNS Zone exists
        priv_dns_client = PrivateDnsManagementClient(credential, subscription_id)
        try:
            zone = priv_dns_client.private_zones.get(resource_group, dns_zone_name)
            logger.info(f"Found Private DNS Zone: {zone.name}")
        except Exception as e:
            logger.error(f"Private DNS zone not found: {str(e)}")
            raise ValueError(f"Create private DNS zone '{dns_zone_name}' first") from e

        # 4. Create the link using exact VNET ID
        link_params = {
            "location": "global",
            "virtual_network": {
                "id": vnet.id  # Using the full ID from the VNET object
            },
            "registration_enabled": False
        }

        # Generate a deterministic link name
        link_name = f"{dns_zone_name}-link-{vnet_name[:20]}".lower().replace('.', '-')

        logger.info(f"Creating link '{link_name}' between VNET and DNS zone...")
        poller = priv_dns_client.virtual_network_links.begin_create_or_update(
            resource_group_name=resource_group,
            private_zone_name=dns_zone_name,
            virtual_network_link_name=link_name,
            parameters=link_params
        )

        # Wait with timeout and progress logging
        start_time = time.time()
        while not poller.done():
            elapsed = time.time() - start_time
            if elapsed > 1800:  # 30 minute timeout
                raise TimeoutError("Linking operation timed out")
            logger.info(f"Waiting for link creation... ({elapsed:.0f}s elapsed)")
            countdown_timer(15)

        result = poller.result()
        logger.info(f"Successfully created link: {result.name}")
        return True

    except Exception as e:
        logger.error(f"Failed to create private DNS link: {str(e)}", exc_info=True)
        return False

def get_vnet_name(subscription_id, resource_group, cluster_name):
    """
    Get the VNET name for an AKS cluster
    """
    try:
        credential = DefaultAzureCredential()
        aks_client = ContainerServiceClient(credential, subscription_id)
        aks_cluster = aks_client.managed_clusters.get(resource_group, cluster_name)
        node_rg = aks_cluster.node_resource_group

        network_client = NetworkManagementClient(credential, subscription_id)
        vnets = network_client.virtual_networks.list(node_rg)
        vnet = next(vnets)  # Get the actual VNET object
        vnet_name = vnet.name
        return vnet_name
    except Exception as e:
        logger.error(f"get_vnet_name: Exception occurred: {e}")
        raise

def perform_vcluster_imports_to_rancher(
        vcluster_tasks: list, config: DotMap, cluster_name: str,
        kubeconfig_path: str):
    """
    Perform All vCluster imports to Rancher
    :arg vcluster_tasks: List of tuples containing vCluster details
    :arg config: Configuration object
    :arg cluster_name: Name of the host cluster
    :arg kubeconfig_path: Path to the kubeconfig file
    """
    successful_imports = 0
    for _, vcluster_name, namespace in vcluster_tasks:
        logger.info(f"Importing vCluster '{vcluster_name}' to Rancher...")
        try:
            import_cluster_to_rancher(
                cluster_name, config.rancher_creds.url,
                config.rancher_creds.access_key, config.rancher_creds.secret_key,
                vcluster_name, namespace, kubeconfig_path)
            successful_imports += 1
        except Exception as e:
            logger.error(f"perform_vcluster_imports_to_rancher: "
                         f"Failed to import {vcluster_name}: {str(e)}")
    logger.info(f"perform_vcluster_imports_to_rancher: "
                f"Total successful imports: {successful_imports}/{len(vcluster_tasks)}")

def verify_if_all_clusters_online(config: DotMap) -> None:
    """
    Verify if all clusters are online in Rancher
    """
    try:
        for cluster_id, command in CREATED_CLUSTERS.items():
            logger.info(f"Verifying cluster {cluster_id}...")
            # Check if the cluster is online
            cluster_state = check_current_cluster_state(
                cluster_id, config.rancher_creds.url,
                config.rancher_creds.access_key, config.rancher_creds.secret_key)
            if cluster_state.lower() == "active":
                logger.info(f"Cluster {cluster_id} is Active.")
            else:
                logger.warning(f"Cluster {cluster_id} is not Active. "
                               f"Current state: {cluster_state}. Retrying apply command...")
                run_apply_command_with_retries(
                    cluster_id, config.rancher_creds.url, config.rancher_creds.access_key,
                    config.rancher_creds.secret_key, command
                )
    finally:
        run_command("rm -rf tmp/*")

def main(config_file_path: str, num_vclusters=None, cleanup_setup_ids=None, unique_id=None) -> int:
    """
    Main function to deploy vClusters and import them to Rancher.
    :param config_file_path: Path to the configuration file
    :param num_vclusters: Number of vClusters to create
    :param cleanup_setup_ids: List of process IDs to clean up
    :param unique_id: Unique ID to include to resource names
    :return:
        Integer: 0 if successful, 1 otherwise
    """
    try:
        start_time = time.time()
        config = read_config_file(config_file_path)
        if cleanup_setup_ids:
            cleanup_module.cleanup_resources(logger, cleanup_setup_ids, config)
            logger.info(f"MAIN: Total time taken: {(time.time() - start_time) / 60:.2f} minutes")
            return 0
        cluster_name = f"systest-zks-test-cluster-{unique_id}"

        create_aks_cluster_with_spot(
            config.azure_creds.subscription_id, config.azure_creds.resource_group, cluster_name,
            config.azure_creds.location, config.azure_creds.vm_size, num_vclusters)
        kubeconfig_path = get_kubeconfig(
            config.azure_creds.subscription_id, config.azure_creds.resource_group, cluster_name)

        # Link VNET to DNS
        link_vnet_to_dns_zone(
            config.azure_creds.subscription_id, config.azure_creds.resource_group,
            config.azure_creds.private_dns_zone_name, cluster_name)

        logger.info(f"MAIN: Importing the host cluster to Rancher {cluster_name}")
        # Import the host cluster to Rancher
        import_cluster_to_rancher(
            cluster_name, config.rancher_creds.url, config.rancher_creds.access_key,
            config.rancher_creds.secret_key, vcluster_name="", namespace="",
            kubeconfig_path=kubeconfig_path, host_cluster_import=True)

        # Deploy vClusters in parallel
        # Set max_workers based on CPU count
        # The goal is not to overload the system, by either using all cores or a percentage of cores
        # OR over threading the system by using all cores
        # Get CPU count, default it to 1 if the command outputs None
        cpu_count = os.cpu_count() or 1
        reserved_cores = max(1, int(cpu_count * 0.25))          # Reserve a percentage of cores (e.g., 25%) or at least 1 core, whichever is larger     # pylint: disable=line-too-long
        adjusted_cpu = max(1, cpu_count - reserved_cores)

        # Set max_workers based on adjusted CPU, capped by num_vclusters
        max_workers = max(1, min(num_vclusters, adjusted_cpu * 2))

        # Deploy vClusters in batches
        vcluster_tasks = []
        batch_size = max(5, min(10, max_workers * 2))
        logger.info(f"System CPU cores: {cpu_count}, Reserved: {reserved_cores}, "
                    f"Adjusted for workload: {adjusted_cpu}")
        logger.info(f"Using max_workers={max_workers}, batch_size={batch_size} for deployment")
        for i in range(0, num_vclusters, batch_size):
            batch_end = min(i + batch_size, num_vclusters)
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                for j in range(i + 1, batch_end + 1):
                    vcluster_name = f"vcluster-{unique_id}-{j}"
                    namespace = f"vcluster-namespace-{unique_id}-{j}"
                    future = executor.submit(
                        deploy_vcluster, cluster_name, namespace, vcluster_name, kubeconfig_path)
                    vcluster_tasks.append((future, vcluster_name, namespace))
                for future, vcluster_name, _ in vcluster_tasks[i:batch_end]:
                    try:
                        future.result()
                        logger.info(f"vCluster '{vcluster_name}' created successfully.")
                    except Exception as e:
                        logger.warning(f"Creation of vCluster '{vcluster_name}' failed: {e}")
            time.sleep(5)  # Wait between batches

        perform_vcluster_imports_to_rancher(
            vcluster_tasks, config, cluster_name, kubeconfig_path)
        # Verify if all clusters are online
        verify_if_all_clusters_online(config)

        logger.info(f"MAIN: Total time taken: {(time.time() - start_time) / 60:.2f} minutes")
        return 0
    except Exception as e:
        logger.error(f"MAIN: Script failed due to exception: {e}")
        return 1

if __name__ == "__main__":
    parser = argparse.ArgumentParser()  # Use 'parser' instead of 'args'
    parser.add_argument("--config", help="Path to the configuration file")
    parser.add_argument(
        "--clusters", help="Number of clusters to create", type=int)
    parser.add_argument(
        "--cleanup", nargs="+", help="Provide one or more Unique IDs (with space) to clean up")
    parser.add_argument(
        "--uid", help="Unique ID for the cluster name (optional)", required=False
    )
    args = parser.parse_args()
    if args.cleanup:
        # If --cleanup is provided, ignore other arguments and proceed only for cleanup
        if args.clusters:
            parser.error("Cannot use --clusters with --cleanup.")
        if not args.config:
            parser.error("Missing --config with --cleanup.")
        main(args.config, cleanup_setup_ids=args.cleanup)
    else:
        uid = args.uid if args.uid else os.getpid()
        # If --cleanup is NOT provided, require --config and --clusters
        if not (args.config and args.clusters):
            parser.error("Both --config and --clusters are required unless using --cleanup.")
        try:
            sys.exit(main(args.config, num_vclusters=args.clusters, unique_id=str(uid)))
        except Exception as e:
            logger.error(f"Script failed: {e}")
            sys.exit(1)

