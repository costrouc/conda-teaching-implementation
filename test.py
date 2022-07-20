import tempfile
import pathlib
import os

import conda

channel_url = "https://conda.anaconda.org/conda-forge"
directory = pathlib.Path(tempfile.gettempdir())

repodata_directory = directory / "repodata"
repodata_directory.mkdir(exist_ok=True)

package_cache_directory = directory / "cache"
package_cache_directory.mkdir(exist_ok=True)

install_directory = directory / "install_directory"

packages = [
    "python >=3.8,<3.9",
    "flask",
]


conda.download_channel(repodata_directory, channel_url)
print(f'Reopdata downloaded: {os.listdir(repodata_directory)}')

available_packages = conda.load_packages(repodata_directory, channel_url)
print(f'Downloaded {len(available_packages)} unique packages')

selected_packages = conda.dummy_solve(available_packages, packages)
for package in selected_packages:
    print(f"{channel_url}/{package['subdir']}/{package['name']}-{package['version']}-{package['build']}.tar.bz2")

conda.download_packages(package_cache_directory, selected_packages, channel_url)
print(f'Cached packages: {os.listdir(package_cache_directory)}')

conda.install_packages(package_cache_directory, install_directory, selected_packages)
