# For Rancher scale test env:

This script expects certain dependencies to be available in the host where it is being run. All those dependencies can be installed by running the install_dependencies.sh.

The dependency installation script is written keeping in mind that the host from which we are running is running a linux operating system.

Since the idea is to create AKS cluster then create vclusters, the script installs azure-cli, kubernetes, vcluster, helm etc. <app_id>, <app_password> and <tenant_id> are required for azure login.

NOTE: The host is not one of the nodes of the cluster. It is just a place where we run the script

## Dependency installation script:

To run install_dependencies.sh,
```aiignore
./install_dependencies.sh -a "<app_id>" -p "<app_password>" -t "<tenant_id>"
```

## Setup Creation:

To create the setup, first get into the virtual environment if created using,
```aiignore
source ~/.venv/bin/activate
```

Run rancher_scale_test_env.py with the following arguments:
```aiignore
python3 rancher_scale_test_env.py --config <config_file_path> --clusters <number_of_vClusters>
```
To create resources with unique IDs in their names:
```aiignore
python3 rancher_scale_test_env.py --config <config_file_path> --clusters <number_of_vClusters> --uid <unique_id>
```
The config_file_path is the path to the json file which contains the configuration for the setup. Refer the config.json file in the repository at kubernetes_tool/config.json.

The number_of_vClusters is the number of vClusters that need to be created.

Upon execution of the script, the following resources are created:
   - AKS cluster
   - vClusters

Then, the vClusters are provisioned to the Rancher of choice (based on info provided in the config file)

## Setup Deletion:

To cleanup the setup created using our script, Run rancher_scale_test_env.py with the following arguments:
```aiignore
python3 rancher_scale_test_env.py --config <config_file_path> --cleanup <unique_id>
```
OR

If you have multiple setups and you want to delete them all at once, you can provide the process_id of each setup separated by space,
```aiignore
python3 rancher_scale_test_env.py --config <config_file_path> --cleanup <unique_id1> <unique_id2> <unique_id3> ...
```
assuming all the setups were created in the same Azure account.

The process_id is the id you see in the resources created as part of the script, 
for e.g. _rancher_scale-test-cluster-18041_ or _vcluster-namespace-18041-2_
As can be seen above, the process ID is 18041. This is the process ID that needs to be passed to the script to delete the setup.

Upon execution of the script, the following resources are deleted:
    - Rancher Cluster entries
    - vClusters
    - AKS cluster
    - Kubeconfig File

